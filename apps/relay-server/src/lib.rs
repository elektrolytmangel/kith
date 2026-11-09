//! kith relay: WebSocket front end around `kith_relay::RoutingTable`.
//!
//! Configuration (environment):
//! - `KITH_RELAY_ADDR`: listen address, default `0.0.0.0:8080`
//! - `KITH_RELAY_AUTH_TIMEOUT_SECS`: seconds a connection has to authenticate, default `10`
//! - abuse limits (REQ-RELAY-006), see [`Limits::from_env`]
//! - `KITH_RELAY_ALLOWED_ORGS`: org IDs (hex root public keys, separated by commas or
//!   whitespace) this relay serves (REQ-RELAY-008). Unset or empty: every org is served.
//! - `KITH_RELAY_AZURE_STORAGE_ACCOUNT` / `KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING`
//!   (feature `azure-state`): read the approved orgs from an Azure Table instead, re-read
//!   every `KITH_RELAY_ALLOWLIST_REFRESH_SECS` (default 30). See [`state`].
//! - `KITH_RELAY_OPEN_ORGS=true`: serve every org even with the Azure state; the list is not read
//!   (REQ-RELAY-009). Not combinable with `KITH_RELAY_ALLOWED_ORGS`.
//! - `KITH_RELAY_PERSIST_REVOCATIONS=true` (with the Azure state): keep revocation notices in a table
//!   and reload them at start (ADR 0014).
//! - `RUST_LOG`: log filter, default `info`
//!
//! Connection: `hello` -> relay `challenge` -> `auth` (signature over
//! [`kith_protocol::auth_message`]). Every other frame is refused until the device
//! has proven it owns its key. Then `announce` lists orgs with membership proofs
//! (certificate chains, ADR 0005), checked against the org ID, which is the org's
//! root public key (REQ-RELAY-004). A device announcing an org without a proof is
//! *pending*: it may only send `invite-claim` (routed to the org's online admins,
//! or the named member, as `claim-deliver`) and receive `direct` messages. Revoked
//! devices can't be pending. Org IDs are compared in canonical (lower-case) form.
//! Revocation notices count only from an admin's announce; removing an admin needs
//! a root-signed notice, and an admin the root removed revokes nobody (ADR 0018).
//! Outboxes, idle connections, connections per address and relay state are
//! bounded (ADR 0019).

pub mod state;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Extension, Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use kith_core::membership::{CertChain, Revocation};
use kith_core::{DeviceId, verify_signature};
use kith_protocol::{
    Frame, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, auth_message, decode, encode, supports_version,
};
use kith_relay::{Role, Route, RoutingTable};
use tokio::sync::{Notify, mpsc};

/// Frames queued for one connection at most (besides the byte budget).
const MAX_QUEUED_FRAMES: usize = 1024;

/// A connection's outbox: a bounded queue of frames with a byte budget, plus a
/// close signal that works even when the queue is full.
#[derive(Clone)]
struct Tx {
    q: mpsc::Sender<(Frame, usize)>,
    queued: Arc<AtomicUsize>,
    budget: usize,
    close: Arc<Notify>,
}

impl Tx {
    fn new(budget: usize) -> (Self, mpsc::Receiver<(Frame, usize)>) {
        let (q, rx) = mpsc::channel(MAX_QUEUED_FRAMES);
        let tx = Self {
            q,
            queued: Arc::new(AtomicUsize::new(0)),
            budget,
            close: Arc::new(Notify::new()),
        };
        (tx, rx)
    }

    /// Ask the connection to close (for example because the device reconnected).
    fn close(&self) {
        self.close.notify_one();
    }
}

/// Queue `frame` (dropped if the connection's outbox is full).
fn send(tx: &Tx, frame: Frame) {
    queue(tx, frame);
}

/// Queue `frame`; `false` if the connection's outbox is full, so the frame was
/// dropped. One frame always fits into an empty outbox.
fn queue(tx: &Tx, frame: Frame) -> bool {
    let n = approx_size(&frame);
    let before = tx.queued.fetch_add(n, Ordering::Relaxed);
    if (before > 0 && before + n > tx.budget) || tx.q.try_send((frame, n)).is_err() {
        tx.queued.fetch_sub(n, Ordering::Relaxed);
        return false;
    }
    true
}

/// Roughly the memory a queued frame holds.
fn approx_size(f: &Frame) -> usize {
    256 + match f {
        Frame::Broadcast { body, .. }
        | Frame::Direct { body, .. }
        | Frame::SyncRequest { body, .. }
        | Frame::InviteClaim { body, .. }
        | Frame::Deliver { body, .. }
        | Frame::ClaimDeliver { body, .. } => body.len(),
        Frame::Presence { online, .. } => online.len() * 80,
        Frame::Receipt { delivered } => delivered.len() * 80,
        Frame::Error { message, .. } => message.len(),
        _ => 0,
    }
}

struct Conn {
    id: u64,
    tx: Tx,
}

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
        fn var<T: std::str::FromStr>(name: &str, default: T) -> T {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        let d = Self::default();
        Self {
            device_frames_per_sec: var("KITH_RELAY_DEVICE_FRAMES_PER_SEC", d.device_frames_per_sec),
            device_burst: var("KITH_RELAY_DEVICE_BURST", d.device_burst),
            device_bytes_per_sec: var("KITH_RELAY_DEVICE_BYTES_PER_SEC", d.device_bytes_per_sec),
            org_frames_per_sec: var("KITH_RELAY_ORG_FRAMES_PER_SEC", d.org_frames_per_sec),
            max_connections: var("KITH_RELAY_MAX_CONNECTIONS", d.max_connections),
            max_message_bytes: var("KITH_RELAY_MAX_MESSAGE_BYTES", d.max_message_bytes),
            max_refused: var("KITH_RELAY_MAX_REFUSED", d.max_refused),
            pending_frames_per_sec: var(
                "KITH_RELAY_PENDING_FRAMES_PER_SEC",
                d.pending_frames_per_sec,
            ),
            max_queued_bytes: var("KITH_RELAY_MAX_QUEUED_BYTES", d.max_queued_bytes),
            write_timeout: Duration::from_secs(var(
                "KITH_RELAY_WRITE_TIMEOUT_SECS",
                d.write_timeout.as_secs(),
            )),
            idle_timeout: Duration::from_secs(var(
                "KITH_RELAY_IDLE_TIMEOUT_SECS",
                d.idle_timeout.as_secs(),
            )),
            max_connections_per_ip: var(
                "KITH_RELAY_MAX_CONNECTIONS_PER_IP",
                d.max_connections_per_ip,
            ),
            client_ip_header: std::env::var("KITH_RELAY_CLIENT_IP_HEADER")
                .ok()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
        }
    }
}

/// Token bucket.
struct Bucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            rate,
            burst,
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
    }

    fn take(&mut self, n: f64) -> bool {
        self.refill();
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// Relay state. Opaque outside this crate; create it with [`new_state`].
pub struct Relay {
    table: RoutingTable,
    conns: HashMap<String, Conn>,
    next_conn: AtomicU64,
    auth_timeout: Duration,
    limits: Limits,
    open: Arc<AtomicUsize>,
    org_buckets: HashMap<String, Bucket>,
    /// Per org, the budget its pending devices share (invite claims).
    pending_buckets: HashMap<String, Bucket>,
    /// Open connections per client address (see [`Limits::max_connections_per_ip`]).
    /// Its own lock, so counting needs no relay lock.
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Revoked devices remembered, all orgs together.
    revoked_total: usize,
    /// Revoked devices per org (REQ-INV-004), with who revoked them. RAM (and
    /// optionally stored, ADR 0014); admins repeat them on announce.
    revoked: HashMap<String, HashMap<String, Revoked>>,
    /// Certificate chains of announced devices: device -> org -> chain, so a
    /// revocation also removes devices certified through the revoked one.
    proofs: HashMap<String, HashMap<String, CertChain>>,
    /// Orgs this relay serves (REQ-RELAY-008); `None` serves every org.
    allowed_orgs: Option<HashSet<String>>,
    /// Newly accepted revocation notices go here when persistence is on ([`state`]).
    persist: Option<mpsc::UnboundedSender<state::RevocationRecord>>,
}

/// How a device was revoked (ADR 0018).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Revoked {
    /// Signed by the org root key. Only such a notice removes an admin.
    by_root: bool,
    /// The notice's time (issuer's clock).
    issued_ms: u64,
}

/// Does a revocation in `set` reach `chain`? A certificate's device counts as
/// revoked if a notice names it, but an admin only through a root-signed one.
fn chain_revoked(chain: &CertChain, set: &HashMap<String, Revoked>) -> bool {
    chain.0.iter().any(|c| {
        set.get(&c.device.to_hex())
            .is_some_and(|e| e.by_root || !c.admin)
    })
}

/// The canonical form of an org ID (lower-case hex of the root key).
fn canonical_org(org: &str) -> Option<String> {
    DeviceId::from_hex(org).ok().map(|d| d.to_hex())
}

/// Revoked devices remembered per org at most (memory bound).
const MAX_REVOKED_PER_ORG: usize = 10_000;
/// Revoked devices remembered at most, all orgs together (memory bound). Notices
/// beyond it are refused and logged; serve only approved orgs to stay clear of it.
const MAX_REVOKED_TOTAL: usize = 200_000;
/// Revocation notices read from one announce at most (all its orgs together).
const MAX_NOTICES_PER_ANNOUNCE: usize = 256;
/// Orgs in one announce at most; a larger announce is refused as a whole.
const MAX_ORGS_PER_ANNOUNCE: usize = 64;
/// Orgs one device may be announced in at the same time.
const MAX_ORGS_PER_DEVICE: usize = 64;

/// Shared relay state (routing table and live connections).
pub type Shared = Arc<Mutex<Relay>>;

/// Where a connection is in the handshake.
enum Session {
    /// Nothing received yet.
    New,
    /// Challenge sent; waiting for the signature.
    Challenged { device: DeviceId, nonce: String },
    /// Device proved key ownership.
    Authed(String),
}

/// Fresh relay state with default [`Limits`]. `auth_timeout` is how long a new
/// connection has to authenticate.
pub fn new_state(auth_timeout: Duration) -> Shared {
    new_state_with(auth_timeout, Limits::default())
}

/// Fresh relay state with the given abuse limits.
pub fn new_state_with(auth_timeout: Duration, limits: Limits) -> Shared {
    Arc::new(Mutex::new(Relay {
        table: RoutingTable::default(),
        conns: HashMap::new(),
        next_conn: AtomicU64::new(0),
        auth_timeout,
        limits,
        open: Arc::new(AtomicUsize::new(0)),
        org_buckets: HashMap::new(),
        pending_buckets: HashMap::new(),
        per_ip: Arc::new(Mutex::new(HashMap::new())),
        revoked_total: 0,
        revoked: HashMap::new(),
        proofs: HashMap::new(),
        allowed_orgs: None,
        persist: None,
    }))
}

/// Parse an org list as given in `KITH_RELAY_ALLOWED_ORGS`: org IDs separated by commas
/// or whitespace, compared case-insensitively. No entries means no restriction (`None`).
pub fn parse_allowed_orgs(list: &str) -> Option<HashSet<String>> {
    let orgs: HashSet<String> = list
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    (!orgs.is_empty()).then_some(orgs)
}

/// Restrict the relay to `orgs` (`None` serves every org). Devices that are online in an
/// org no longer on the list are removed from it and told (`org-not-allowed`); their
/// connections stay open for their other orgs.
pub fn set_allowed_orgs(state: &Shared, orgs: Option<HashSet<String>>) {
    let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
    r.allowed_orgs = orgs;
    let Some(allowed) = r.allowed_orgs.clone() else {
        return;
    };
    for org in r.table.orgs() {
        if allowed.contains(&org.to_ascii_lowercase()) {
            continue;
        }
        for dev in r.table.devices_in(&org) {
            r.table.kick(&dev, &org);
            if let Some(m) = r.proofs.get_mut(&dev) {
                m.remove(&org);
            }
            if let Some(conn) = r.conns.get(&dev) {
                send(
                    &conn.tx,
                    error(
                        "org-not-allowed",
                        format!("{org}: this relay no longer serves this organization"),
                    ),
                );
            }
        }
        forget_if_empty(&mut r, &org);
    }
}

/// Counts an open connection for as long as it lives.
struct OpenGuard(Arc<AtomicUsize>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The relay's HTTP/WebSocket routes (`/healthz`, `/v1/ws`).
pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    let (open, limits, per_ip) = {
        let r = state.lock().unwrap_or_else(PoisonError::into_inner);
        (r.open.clone(), r.limits.clone(), r.per_ip.clone())
    };
    let ip = peer.and_then(|Extension(ConnectInfo(addr))| {
        client_ip(addr.ip(), &headers, limits.client_ip_header.as_deref())
    });
    let ip_guard = match ip {
        Some(ip) if limits.max_connections_per_ip > 0 => {
            let mut m = per_ip.lock().unwrap_or_else(PoisonError::into_inner);
            let n = m.entry(ip).or_default();
            if *n >= limits.max_connections_per_ip {
                return (StatusCode::TOO_MANY_REQUESTS, "too many connections").into_response();
            }
            *n += 1;
            Some(IpGuard(per_ip.clone(), ip))
        }
        _ => None,
    };
    if open.fetch_add(1, Ordering::Relaxed) >= limits.max_connections {
        open.fetch_sub(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
    }
    let guard = OpenGuard(open);
    ws.max_message_size(limits.max_message_bytes)
        .max_frame_size(limits.max_message_bytes)
        .on_upgrade(move |socket| async move {
            let _guards = (guard, ip_guard);
            connection(socket, state, limits).await
        })
}

/// The address a connection is counted under: the TCP peer, or the last entry of
/// `header` (set by a trusted proxy) when configured. IPv6 addresses count per /64.
fn client_ip(peer: IpAddr, headers: &HeaderMap, header: Option<&str>) -> Option<IpAddr> {
    let ip = match header {
        Some(h) => headers
            .get_all(h)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer),
        None => peer,
    };
    Some(match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    })
}

/// Counts a connection for its client address for as long as it lives.
struct IpGuard(Arc<Mutex<HashMap<IpAddr, usize>>>, IpAddr);

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

async fn connection(mut socket: WebSocket, state: Shared, limits: Limits) {
    let mut frames = Bucket::new(limits.device_frames_per_sec, limits.device_burst);
    let mut bytes = Bucket::new(
        limits.device_bytes_per_sec,
        limits.device_bytes_per_sec * 4.0,
    );
    let mut refused = 0u32;
    let (tx, mut rx) = Tx::new(limits.max_queued_bytes);
    let (conn_id, auth_timeout) = {
        let r = state.lock().unwrap_or_else(PoisonError::into_inner);
        (r.next_conn.fetch_add(1, Ordering::Relaxed), r.auth_timeout)
    };
    let mut session = Session::New;
    let deadline = tokio::time::sleep(auth_timeout);
    tokio::pin!(deadline);
    let idle = limits.idle_timeout;
    let mut ping = tokio::time::interval(if idle.is_zero() {
        Duration::from_secs(3600)
    } else {
        idle / 3
    });
    ping.tick().await; // the first tick is immediate
    let mut last_heard = Instant::now();
    let write = limits.write_timeout;
    let close = tx.close.clone();

    loop {
        let authed = matches!(session, Session::Authed(_));
        tokio::select! {
            out = rx.recv() => match out {
                Some((f, n)) => {
                    tx.queued.fetch_sub(n, Ordering::Relaxed);
                    let Ok(bytes) = encode(&f) else { continue };
                    // A device that does not read is closed, not buffered for.
                    if !matches!(
                        tokio::time::timeout(write, socket.send(Message::Binary(bytes.into()))).await,
                        Ok(Ok(()))
                    ) {
                        tracing::debug!("write failed or timed out; closing");
                        break;
                    }
                }
                None => break,
            },
            () = close.notified() => break,
            () = &mut deadline, if !authed => {
                tracing::debug!("authentication timed out");
                send_now(&mut socket, error("auth-timeout", "authenticate within the time limit".into()), write).await;
                break;
            }
            _ = ping.tick(), if !idle.is_zero() => {
                if last_heard.elapsed() >= idle {
                    tracing::debug!("idle timeout");
                    send_now(&mut socket, error("idle-timeout", "nothing received; closing".into()), write).await;
                    break;
                }
                if !matches!(
                    tokio::time::timeout(write, socket.send(Message::Ping(Vec::new().into()))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            msg = socket.recv() => {
                let Some(Ok(msg)) = msg else { break };
                last_heard = Instant::now();
                let raw = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                // Abuse limits (REQ-RELAY-006): drop excess frames, close persistent abusers.
                if !(frames.take(1.0) && bytes.take(raw.len() as f64)) {
                    refused += 1;
                    if refused >= limits.max_refused {
                        send_now(&mut socket, error("rate-limited", "too many frames; closing".into()), write).await;
                        break;
                    }
                    if refused.is_power_of_two() {
                        send(&tx, error("rate-limited", "slow down: frame dropped".into()));
                    }
                    continue;
                }
                refused = 0;
                match decode(&raw) {
                    Ok(frame) => {
                        // Signatures are checked here, without the relay lock; an
                        // announce (many signatures) on the blocking pool.
                        let checked = if matches!(frame, Frame::Announce { .. }) {
                            let device = match &session {
                                Session::Authed(d) => Some(d.clone()),
                                _ => None,
                            };
                            match tokio::task::spawn_blocking(move || check_frame(frame, None, device.as_deref())).await {
                                Ok(c) => c,
                                Err(_) => break,
                            }
                        } else {
                            check_frame(frame, Some(&session), None)
                        };
                        if handle(checked, &mut session, conn_id, &tx, &state) == Flow::Close {
                            // Flush the queued error frame, then hang up.
                            while let Ok((f, _)) = rx.try_recv() {
                                send_now(&mut socket, f, write).await;
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        send(&tx, error("bad-frame", e.to_string()));
                    }
                }
            }
        }
    }

    // Say goodbye properly so clients see a clean close, not a reset.
    let _ = tokio::time::timeout(write, socket.send(Message::Close(None))).await;

    if let Session::Authed(d) = session {
        let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
        // A newer connection of the same device may have replaced this one; only
        // clean up if this connection still owns the device's slot.
        if r.conns.get(&d).is_some_and(|c| c.id == conn_id) {
            let orgs = r.table.orgs_of(&d);
            r.table.disconnect(&d);
            for org in orgs {
                forget_if_empty(&mut r, &org);
            }
            r.proofs.remove(&d);
            r.conns.remove(&d);
            tracing::debug!(device = %d, "disconnected");
        }
    }
}

async fn send_now(socket: &mut WebSocket, frame: Frame, write: Duration) {
    if let Ok(bytes) = encode(&frame) {
        let _ = tokio::time::timeout(write, socket.send(Message::Binary(bytes.into()))).await;
    }
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Close,
}

/// A frame with its signatures checked. Checking needs no shared state, so it
/// happens before the relay lock is taken.
enum Checked {
    /// `auth`, with whether its signature matches the challenged key.
    Auth(bool),
    /// `announce`, each org's proof and notices checked.
    Announce(Vec<CheckedOrg>),
    /// Refused as a whole with this error.
    Refuse(Frame),
    /// Any other frame, unchanged.
    Frame(Frame),
}

/// One org of an announce, its signatures checked.
struct CheckedOrg {
    /// Canonical org ID.
    org: String,
    always_on: bool,
    /// The role the proof gives (signatures only; revocations are checked under the lock).
    proof: Result<(Role, Option<CertChain>), &'static str>,
    /// Whether the announce carried revocation notices for this org.
    sent_notices: bool,
    /// The notices, verified, with their hex form (only for an admin's proof).
    notices: Vec<Result<(Revocation, String), String>>,
}

/// Check the signatures in `frame`: an `auth` against the challenge in `session`,
/// an `announce` by the authenticated `device`.
fn check_frame(frame: Frame, session: Option<&Session>, device: Option<&str>) -> Checked {
    match (frame, session, device) {
        (Frame::Auth { signature }, Some(Session::Challenged { device, nonce }), _) => {
            let sig = hex::decode(&signature)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok());
            Checked::Auth(sig.is_some_and(|s| {
                verify_signature(device, &auth_message(&device.to_hex(), nonce), &s).is_ok()
            }))
        }
        (frame @ Frame::Announce { .. }, _, Some(d)) => {
            let orgs = match canonical_frame(frame) {
                Ok(Frame::Announce { orgs }) => orgs,
                Ok(other) => return Checked::Frame(other),
                Err(org) => return Checked::Refuse(bad_org(&org)),
            };
            if orgs.len() > MAX_ORGS_PER_ANNOUNCE {
                return Checked::Refuse(error(
                    "too-many-orgs",
                    format!("announce at most {MAX_ORGS_PER_ANNOUNCE} orgs at a time"),
                ));
            }
            let mut budget = MAX_NOTICES_PER_ANNOUNCE;
            let checked = orgs
                .into_iter()
                .map(|m| {
                    let proof = verify_proof(&m.org, d, &m.proof);
                    let mut notices = vec![];
                    if matches!(proof, Ok((Role::Admin, _))) {
                        let org_key = DeviceId::from_hex(&m.org).expect("canonical");
                        let take = m.revoked.len().min(budget);
                        budget -= take;
                        notices = m
                            .revoked
                            .iter()
                            .take(take)
                            .map(|n| verify_notice(&org_key, n).map(|rev| (rev, n.clone())))
                            .collect();
                    }
                    CheckedOrg {
                        sent_notices: !m.revoked.is_empty(),
                        org: m.org,
                        always_on: m.always_on,
                        proof,
                        notices,
                    }
                })
                .collect();
            Checked::Announce(checked)
        }
        (frame, _, _) => Checked::Frame(frame),
    }
}

fn handle(checked: Checked, session: &mut Session, conn_id: u64, tx: &Tx, state: &Shared) -> Flow {
    let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
    // Handshake first: nothing else is accepted before the device is authenticated.
    match (&*session, checked) {
        (Session::New, Checked::Frame(Frame::Hello { version, device })) => {
            if !supports_version(version) {
                send(
                    tx,
                    error(
                        "version",
                        format!("relay speaks v{MIN_PROTOCOL_VERSION} to v{PROTOCOL_VERSION}"),
                    ),
                );
                return Flow::Close;
            }
            let Ok(id) = DeviceId::from_hex(&device) else {
                send(
                    tx,
                    error(
                        "bad-device",
                        "device must be a hex Ed25519 public key".into(),
                    ),
                );
                return Flow::Close;
            };
            let nonce = hex::encode(kith_core::random_bytes::<32>());
            send(
                tx,
                Frame::Challenge {
                    nonce: nonce.clone(),
                },
            );
            *session = Session::Challenged { device: id, nonce };
            Flow::Continue
        }
        (Session::Challenged { device, .. }, Checked::Auth(ok)) => {
            if !ok {
                send(
                    tx,
                    error(
                        "auth-failed",
                        "signature does not match the device key".into(),
                    ),
                );
                return Flow::Close;
            }
            let device_hex = device.to_hex();
            // A reconnecting device replaces its old connection, which is closed.
            if let Some(old) = r.conns.insert(
                device_hex.clone(),
                Conn {
                    id: conn_id,
                    tx: tx.clone(),
                },
            ) {
                old.tx.close();
            }
            tracing::debug!(device = %device_hex, "authenticated");
            *session = Session::Authed(device_hex);
            Flow::Continue
        }
        (Session::Authed(_), Checked::Frame(Frame::Hello { .. } | Frame::Auth { .. })) => {
            send(tx, error("unsupported", "already authenticated".into()));
            Flow::Continue
        }
        (Session::Authed(d), Checked::Announce(orgs)) => {
            let d = d.clone();
            announce(orgs, &d, tx, &mut r);
            Flow::Continue
        }
        (Session::Authed(_), Checked::Refuse(f)) => {
            send(tx, f);
            Flow::Continue
        }
        (Session::Authed(d), Checked::Frame(frame)) => {
            let d = d.clone();
            route(frame, &d, tx, &mut r);
            Flow::Continue
        }
        (Session::New, _) => {
            send(tx, error("unauthenticated", "send hello first".into()));
            Flow::Continue
        }
        (Session::Challenged { .. } | Session::Authed(_), _) => {
            send(
                tx,
                error(
                    "unauthenticated",
                    "answer the challenge with auth first".into(),
                ),
            );
            Flow::Continue
        }
    }
}

/// The role a membership proof gives `device` in `org` (REQ-RELAY-004), from its
/// signatures alone. An empty proof means "joining": pending.
fn verify_proof(
    org: &str,
    device: &str,
    proof: &str,
) -> Result<(Role, Option<CertChain>), &'static str> {
    let org_key = DeviceId::from_hex(org).map_err(|_| "org ID must be the hex org root key")?;
    if proof.is_empty() {
        return Ok((Role::Pending, None));
    }
    let device = DeviceId::from_hex(device).map_err(|_| "bad device")?;
    let chain = CertChain::from_hex(proof).map_err(|_| "malformed membership proof")?;
    let proven = chain
        .verify(&org_key, &device)
        .map_err(|_| "membership proof does not verify")?;
    let role = if proven.admin {
        Role::Admin
    } else {
        Role::Member
    };
    Ok((role, Some(chain)))
}

/// Refuse a device a revocation reaches: through its chain, or, pending (no
/// chain), by name. A revoked device does not come back as a newcomer.
fn not_revoked(
    device: &str,
    chain: Option<&CertChain>,
    revoked: Option<&HashMap<String, Revoked>>,
) -> Result<(), &'static str> {
    let hit = revoked.is_some_and(|set| match chain {
        Some(c) => chain_revoked(c, set),
        None => set.contains_key(device),
    });
    if hit {
        Err("device was revoked")
    } else {
        Ok(())
    }
}

/// Parse and verify one revocation notice against the org key.
pub(crate) fn verify_notice(org_key: &DeviceId, notice: &str) -> Result<Revocation, String> {
    Revocation::from_hex(notice)
        .and_then(|rev| rev.verify(org_key).map(|_| rev))
        .map_err(|e| e.to_string())
}

/// Remember a verified notice's device as revoked; `Ok(true)` if it changed
/// anything. A notice by an admin the root revoked does not count (when `loading`
/// stored notices: unless it is older than that revocation). New notices are
/// handed to the persistence writer when it is on.
pub(crate) fn remember_verified(
    r: &mut Relay,
    org: &str,
    rev: &Revocation,
    notice: &str,
    loading: bool,
) -> Result<bool, String> {
    let device = rev.device.to_hex();
    let set = r.revoked.get(org);
    if !rev.by_root()
        && let Some(e) = set
            .and_then(|s| s.get(&rev.issuer.to_hex()))
            .filter(|e| e.by_root)
        && !(loading && rev.issued_ms < e.issued_ms)
    {
        return Err("the issuer was revoked".into());
    }
    let entry = Revoked {
        by_root: rev.by_root(),
        issued_ms: rev.issued_ms,
    };
    let new = match set.and_then(|s| s.get(&device)) {
        Some(e) if e.by_root || !entry.by_root => false,
        // A root notice for a device only an admin had revoked.
        Some(_) => true,
        None if set.map_or(0, HashMap::len) >= MAX_REVOKED_PER_ORG => false,
        None if r.revoked_total >= MAX_REVOKED_TOTAL => {
            tracing::warn!(%org, "the relay's revocation list is full; a notice was not kept");
            return Err("the relay's revocation list is full".into());
        }
        None => {
            r.revoked_total += 1;
            true
        }
    };
    if !new {
        return Ok(false);
    }
    r.revoked
        .entry(org.to_string())
        .or_default()
        .insert(device.clone(), entry);
    if let Some(tx) = &r.persist {
        let _ = tx.send(state::RevocationRecord {
            org: org.to_string(),
            device,
            notice: notice.to_string(),
        });
    }
    Ok(true)
}

/// Verify and remember the revocation notices of an announce, then remove every
/// online device of `org` they affect (the revoked ones and devices certified
/// through them). Bad notices are ignored with an error to `tx`.
fn apply_revocations(
    r: &mut Relay,
    org: &str,
    notices: Vec<Result<(Revocation, String), String>>,
    tx: &Tx,
) {
    let mut added = false;
    for n in notices {
        match n.and_then(|(rev, hex)| remember_verified(r, org, &rev, &hex, false)) {
            Ok(new) => added |= new,
            Err(e) => {
                send(tx, error("bad-revocation", format!("{org}: {e}")));
            }
        }
    }
    if !added {
        return;
    }
    let set = r.revoked.get(org).cloned().unwrap_or_default();
    let affected: Vec<String> = r
        .table
        .devices_in(org)
        .into_iter()
        .filter(|dev| {
            match r.proofs.get(dev).and_then(|m| m.get(org)) {
                Some(c) => chain_revoked(c, &set),
                // Pending devices have no chain.
                None => set.contains_key(dev),
            }
        })
        .collect();
    for dev in &affected {
        r.table.kick(dev, org);
        if let Some(m) = r.proofs.get_mut(dev) {
            m.remove(org);
        }
        if let Some(conn) = r.conns.get(dev) {
            send(
                &conn.tx,
                error("revoked", format!("{org}: device was removed")),
            );
        }
    }
    forget_if_empty(r, org);
    let online = r.table.online(org);
    fan_out(r, &online, || Frame::Presence {
        org: org.to_string(),
        online: online.clone(),
    });
}

/// Take one routed frame from `org`'s bucket, or its pending devices' bucket.
fn org_allows(r: &mut Relay, org: &str, pending: bool) -> bool {
    let (map, rate) = if pending {
        (&mut r.pending_buckets, r.limits.pending_frames_per_sec)
    } else {
        (&mut r.org_buckets, r.limits.org_frames_per_sec)
    };
    map.entry(org.to_string())
        .or_insert_with(|| Bucket::new(rate, rate * 2.0))
        .take(1.0)
}

/// Drop an org's rate buckets once none of its devices is online. Buckets exist only
/// for orgs with devices online, so their number stays bounded.
fn forget_if_empty(r: &mut Relay, org: &str) {
    if r.table.devices_in(org).is_empty() {
        r.org_buckets.remove(org);
        r.pending_buckets.remove(org);
    }
}

fn bad_org(org: &str) -> Frame {
    error(
        "bad-org",
        format!("{org}: org ID must be the hex org root key"),
    )
}

/// Apply an announce whose signatures are checked: join each org with the role its
/// proof gives, unless a revocation reaches the device. Only an admin's announce
/// feeds revocation notices, and they may revoke the announcer itself.
fn announce(orgs: Vec<CheckedOrg>, d: &str, tx: &Tx, r: &mut Relay) {
    for m in orgs {
        if let Some(allowed) = &r.allowed_orgs
            && !allowed.contains(&m.org)
        {
            send(
                tx,
                error(
                    "org-not-allowed",
                    format!("{}: this relay does not serve this organization", m.org),
                ),
            );
            continue;
        }
        let refuse = |why: &str| {
            let code = if why == "device was revoked" {
                "revoked"
            } else {
                "bad-proof"
            };
            send(tx, error(code, format!("{}: {why}", m.org)));
        };
        if r.table.role(&m.org, d).is_none() && r.table.orgs_of(d).len() >= MAX_ORGS_PER_DEVICE {
            send(
                tx,
                error(
                    "too-many-orgs",
                    format!(
                        "{}: a device is in at most {MAX_ORGS_PER_DEVICE} orgs at a time",
                        m.org
                    ),
                ),
            );
            continue;
        }
        let (role, chain) = match m.proof {
            Ok(x) => x,
            Err(why) => {
                refuse(why);
                continue;
            }
        };
        if let Err(why) = not_revoked(d, chain.as_ref(), r.revoked.get(&m.org)) {
            refuse(why);
            continue;
        }
        if m.sent_notices {
            if role != Role::Admin {
                send(
                    tx,
                    error(
                        "bad-revocation",
                        format!("{}: only admins send revocation notices", m.org),
                    ),
                );
            } else {
                apply_revocations(r, &m.org, m.notices, tx);
                if let Err(why) = not_revoked(d, chain.as_ref(), r.revoked.get(&m.org)) {
                    refuse(why);
                    continue;
                }
            }
        }
        match chain {
            Some(c) => {
                r.proofs
                    .entry(d.to_string())
                    .or_default()
                    .insert(m.org.clone(), c);
            }
            None => {
                if let Some(p) = r.proofs.get_mut(d) {
                    p.remove(&m.org);
                }
            }
        }
        r.table.join_as(d, &m.org, role);
        r.table
            .set_always_on(d, m.always_on && role != Role::Pending);
        if role != Role::Pending {
            let online = r.table.online(&m.org);
            fan_out(r, &online, || Frame::Presence {
                org: m.org.clone(),
                online: online.clone(),
            });
        }
    }
}

fn route(frame: Frame, d: &str, tx: &Tx, r: &mut Relay) {
    // One spelling per org, so revocations and routing see the same org.
    let frame = match canonical_frame(frame) {
        Ok(f) => f,
        Err(org) => {
            send(tx, bad_org(&org));
            return;
        }
    };
    let member =
        |r: &Relay, org: &str| matches!(r.table.role(org, d), Some(Role::Member | Role::Admin));
    let routed_org = match &frame {
        Frame::Broadcast { org, .. }
        | Frame::Direct { org, .. }
        | Frame::SyncRequest { org, .. }
        | Frame::InviteClaim { org, .. } => Some(org.clone()),
        _ => None,
    };
    if let Some(org) = routed_org
        && let Some(role) = r.table.role(&org, d)
        && !org_allows(r, &org, role == Role::Pending)
    {
        send(
            tx,
            error(
                "rate-limited",
                format!("org {org} is over its limit; frame dropped"),
            ),
        );
        return;
    }
    match frame {
        Frame::Broadcast { org, body } if member(r, &org) => {
            let route = r.table.broadcast(&org, d);
            deliver(r, route, tx, org, d, body);
        }
        Frame::Direct { org, to, body } if member(r, &org) => {
            let route = r.table.direct(&org, &to);
            deliver(r, route, tx, org, d, body);
        }
        Frame::SyncRequest { org, body } if member(r, &org) => {
            let route = r.table.sync_partner(&org, d);
            deliver(r, route, tx, org, d, body);
        }
        Frame::InviteClaim { org, body, to, .. } if r.table.role(&org, d).is_some() => {
            let route = match to {
                Some(to) => r.table.member(&org, &to),
                None => r.table.admins(&org),
            };
            // Its own frame type: the receiver takes nothing but a claim from it.
            let delivered = match route {
                Route::To(devs) => fan_out(r, &devs, || Frame::ClaimDeliver {
                    org: org.clone(),
                    from: d.into(),
                    body: body.clone(),
                }),
                Route::Dropped => vec![],
            };
            send(tx, Frame::Receipt { delivered });
        }
        Frame::Broadcast { org, .. }
        | Frame::Direct { org, .. }
        | Frame::SyncRequest { org, .. }
        | Frame::InviteClaim { org, .. } => send(
            tx,
            error(
                "not-a-member",
                format!("announce {org} with a valid proof first"),
            ),
        ),
        // Never echo the frame: it is the client's input, of any size.
        _ => send(
            tx,
            error("unsupported", "frame type not accepted from clients".into()),
        ),
    }
}

/// `frame` with its org IDs in canonical form; `Err(org)` for an invalid one.
fn canonical_frame(frame: Frame) -> Result<Frame, String> {
    let canon = |org: String| canonical_org(&org).ok_or(org);
    Ok(match frame {
        Frame::Announce { orgs } => Frame::Announce {
            orgs: orgs
                .into_iter()
                .map(|m| {
                    Ok(kith_protocol::Membership {
                        org: canon(m.org)?,
                        ..m
                    })
                })
                .collect::<Result<_, String>>()?,
        },
        Frame::Broadcast { org, body } => Frame::Broadcast {
            org: canon(org)?,
            body,
        },
        Frame::Direct { org, to, body } => Frame::Direct {
            org: canon(org)?,
            to,
            body,
        },
        Frame::SyncRequest { org, body } => Frame::SyncRequest {
            org: canon(org)?,
            body,
        },
        Frame::InviteClaim {
            org,
            token,
            body,
            to,
        } => Frame::InviteClaim {
            org: canon(org)?,
            token,
            body,
            to,
        },
        other => other,
    })
}

fn deliver(r: &Relay, route: Route, tx: &Tx, org: String, from: &str, body: Vec<u8>) {
    let delivered = match route {
        Route::To(devs) => fan_out(r, &devs, || Frame::Deliver {
            org: org.clone(),
            from: from.into(),
            body: body.clone(),
        }),
        Route::Dropped => vec![],
    };
    send(tx, Frame::Receipt { delivered });
}

/// Queue a frame for each of `to`; the devices it was queued for. A device whose
/// outbox is full misses it (it catches up by sync).
fn fan_out(r: &Relay, to: &[String], make: impl Fn() -> Frame) -> Vec<String> {
    to.iter()
        .filter(|d| r.conns.get(*d).is_some_and(|conn| queue(&conn.tx, make())))
        .cloned()
        .collect()
}

fn error(code: &str, message: String) -> Frame {
    Frame::Error {
        code: code.into(),
        message,
    }
}

#[cfg(test)]
mod tests;
