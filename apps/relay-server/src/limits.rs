//! Abuse limits (REQ-RELAY-006) and the token bucket behind them.

use super::*;

/// Abuse limits (REQ-RELAY-006). Excess frames are dropped with a `rate-limited`
/// error; a connection that keeps going far beyond its limit is closed.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Frames per second per connection (sustained).
    pub device_frames_per_sec: f64,
    /// Frames a connection may send in a burst.
    pub device_burst: f64,
    /// Message bytes per second per connection (sustained; bursts up to 4 s worth).
    pub device_bytes_per_sec: f64,
    /// Routed frames per second per organization (all its devices together).
    pub org_frames_per_sec: f64,
    /// Open WebSocket connections at most; more are refused with HTTP 503.
    pub max_connections: usize,
    /// Largest WebSocket message in bytes (a 1 MiB body is about 3.5 MiB as JSON).
    pub max_message_bytes: usize,
    /// Close a connection after this many refused frames in a row.
    pub max_refused: u32,
    /// Frames per second per org from its *pending* devices together (invite claims);
    /// they do not use the org's own budget. Bursts up to twice this.
    pub pending_frames_per_sec: f64,
    /// Bytes queued for one connection at most; frames for a device whose outbox is
    /// full are dropped (and left out of the sender's receipt).
    pub max_queued_bytes: usize,
    /// A connection whose socket takes longer than this to accept a frame is closed.
    pub write_timeout: Duration,
    /// A connection that sends nothing (not even a pong to the relay's pings) for this
    /// long is closed. The relay pings every third of it. Zero: no idle timeout.
    pub idle_timeout: Duration,
    /// Open connections per client address at most (IPv6: per /64). Zero: no limit.
    /// Needs the server to provide connection info (the binary does).
    pub max_connections_per_ip: usize,
    /// Take the client address from this header (last entry), set by a trusted proxy in
    /// front of the relay (for example `x-forwarded-for`). Unset: the TCP peer address.
    pub client_ip_header: Option<String>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            device_frames_per_sec: 100.0,
            device_burst: 200.0,
            device_bytes_per_sec: 4.0 * 1024.0 * 1024.0,
            org_frames_per_sec: 1000.0,
            max_connections: 10_000,
            max_message_bytes: 4 * 1024 * 1024,
            max_refused: 200,
            pending_frames_per_sec: 10.0,
            max_queued_bytes: 16 * 1024 * 1024,
            write_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            max_connections_per_ip: 100,
            client_ip_header: None,
        }
    }
}

impl Limits {
    /// Defaults, overridden by `KITH_RELAY_DEVICE_FRAMES_PER_SEC`,
    /// `KITH_RELAY_DEVICE_BURST`, `KITH_RELAY_DEVICE_BYTES_PER_SEC`,
    /// `KITH_RELAY_ORG_FRAMES_PER_SEC`, `KITH_RELAY_MAX_CONNECTIONS`,
    /// `KITH_RELAY_MAX_MESSAGE_BYTES`, `KITH_RELAY_MAX_REFUSED`,
    /// `KITH_RELAY_PENDING_FRAMES_PER_SEC`, `KITH_RELAY_MAX_QUEUED_BYTES`,
    /// `KITH_RELAY_WRITE_TIMEOUT_SECS`, `KITH_RELAY_IDLE_TIMEOUT_SECS`,
    /// `KITH_RELAY_MAX_CONNECTIONS_PER_IP`, `KITH_RELAY_CLIENT_IP_HEADER`.
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Like [`Self::from_env`], reading the variables through `lookup` (testable
    /// without changing the process environment). A value that does not parse
    /// falls back to the default.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        fn var<T: std::str::FromStr>(
            lookup: &impl Fn(&str) -> Option<String>,
            name: &str,
            default: T,
        ) -> T {
            lookup(name).and_then(|v| v.parse().ok()).unwrap_or(default)
        }
        let d = Self::default();
        Self {
            device_frames_per_sec: var(
                &lookup,
                "KITH_RELAY_DEVICE_FRAMES_PER_SEC",
                d.device_frames_per_sec,
            ),
            device_burst: var(&lookup, "KITH_RELAY_DEVICE_BURST", d.device_burst),
            device_bytes_per_sec: var(
                &lookup,
                "KITH_RELAY_DEVICE_BYTES_PER_SEC",
                d.device_bytes_per_sec,
            ),
            org_frames_per_sec: var(
                &lookup,
                "KITH_RELAY_ORG_FRAMES_PER_SEC",
                d.org_frames_per_sec,
            ),
            max_connections: var(&lookup, "KITH_RELAY_MAX_CONNECTIONS", d.max_connections),
            max_message_bytes: var(&lookup, "KITH_RELAY_MAX_MESSAGE_BYTES", d.max_message_bytes),
            max_refused: var(&lookup, "KITH_RELAY_MAX_REFUSED", d.max_refused),
            pending_frames_per_sec: var(
                &lookup,
                "KITH_RELAY_PENDING_FRAMES_PER_SEC",
                d.pending_frames_per_sec,
            ),
            max_queued_bytes: var(&lookup, "KITH_RELAY_MAX_QUEUED_BYTES", d.max_queued_bytes),
            write_timeout: Duration::from_secs(var(
                &lookup,
                "KITH_RELAY_WRITE_TIMEOUT_SECS",
                d.write_timeout.as_secs(),
            )),
            idle_timeout: Duration::from_secs(var(
                &lookup,
                "KITH_RELAY_IDLE_TIMEOUT_SECS",
                d.idle_timeout.as_secs(),
            )),
            max_connections_per_ip: var(
                &lookup,
                "KITH_RELAY_MAX_CONNECTIONS_PER_IP",
                d.max_connections_per_ip,
            ),
            client_ip_header: lookup("KITH_RELAY_CLIENT_IP_HEADER")
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
        }
    }
}

/// Token bucket.
pub(crate) struct Bucket {
    pub(crate) tokens: f64,
    pub(crate) rate: f64,
    pub(crate) burst: f64,
    pub(crate) last: Instant,
}

impl Bucket {
    pub(crate) fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            rate,
            burst,
            last: Instant::now(),
        }
    }

    pub(crate) fn refill(&mut self) {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
    }

    pub(crate) fn take(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}
