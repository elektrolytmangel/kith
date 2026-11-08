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
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use kith_client::{auth_frame, hello_frame};
    use kith_core::Signer;
    use kith_core::membership::MembershipCert;
    use kith_crypto::DeviceKey;
    use kith_protocol::Membership;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};

    type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    async fn start(auth_timeout: Duration) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app(new_state(auth_timeout)))
                .await
                .unwrap();
        });
        url
    }

    async fn send_frame(ws: &mut Ws, f: &Frame) {
        ws.send(tungstenite::Message::Binary(encode(f).unwrap().into()))
            .await
            .unwrap();
    }

    /// Next frame, or `None` if the connection was closed.
    async fn next_frame(ws: &mut Ws) -> Option<Frame> {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("timed out waiting for the relay");
            match msg {
                Some(Ok(tungstenite::Message::Binary(b))) => return Some(decode(&b).unwrap()),
                Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_)) => return None,
                Some(Ok(_)) => continue,
            }
        }
    }

    async fn connect(url: &str) -> Ws {
        connect_async(url).await.unwrap().0
    }

    /// Full handshake; returns the authenticated socket.
    async fn login(url: &str, key: &DeviceKey) -> Ws {
        let mut ws = connect(url).await;
        send_frame(&mut ws, &hello_frame(key)).await;
        let Some(Frame::Challenge { nonce }) = next_frame(&mut ws).await else {
            panic!("expected challenge");
        };
        send_frame(&mut ws, &auth_frame(key, &nonce)).await;
        ws
    }

    fn org_id(root: &DeviceKey) -> String {
        root.device_id().to_hex()
    }

    /// A membership proof for `key` in `root`'s org, issued by the root.
    fn proof(root: &DeviceKey, key: &DeviceKey, admin: bool) -> String {
        CertChain(vec![MembershipCert::issue(
            root,
            root.device_id(),
            key.device_id(),
            admin,
            1,
        )])
        .to_hex()
    }

    async fn announce(ws: &mut Ws, org: &str, proof: String) {
        send_frame(
            ws,
            &Frame::Announce {
                orgs: vec![Membership {
                    org: org.into(),
                    proof,
                    always_on: false,
                    revoked: vec![],
                }],
            },
        )
        .await;
    }

    /// Announce `key` as a member of `root`'s org.
    async fn join(ws: &mut Ws, root: &DeviceKey, key: &DeviceKey) {
        announce(ws, &org_id(root), proof(root, key, false)).await;
        // Our own join is announced to us as presence.
        assert!(matches!(next_frame(ws).await, Some(Frame::Presence { .. })));
    }

    /// Skip presence updates until the next error, and check its code.
    async fn expect_error_after_presence(ws: &mut Ws, code: &str) {
        loop {
            match next_frame(ws).await {
                Some(Frame::Presence { .. }) => continue,
                other => return expect_error(other, code),
            }
        }
    }

    fn member_cert_hex(cert: &MembershipCert) -> String {
        CertChain(vec![cert.clone()]).to_hex()
    }

    fn expect_error(f: Option<Frame>, code: &str) {
        match f {
            Some(Frame::Error { code: c, .. }) => assert_eq!(c, code),
            other => panic!("expected error {code}, got {other:?}"),
        }
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn authenticated_devices_can_exchange_messages() {
        let url = start(Duration::from_secs(10)).await;
        let (root, ka, kb) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        // a sees b come online.
        assert!(matches!(
            next_frame(&mut a).await,
            Some(Frame::Presence { .. })
        ));

        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org_id(&root),
                body: b"hi".to_vec(),
            },
        )
        .await;
        assert!(
            matches!(next_frame(&mut a).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
        );
        match next_frame(&mut b).await {
            Some(Frame::Deliver { from, body, .. }) => {
                assert_eq!(from, ka.device_id().to_hex());
                assert_eq!(body, b"hi");
            }
            other => panic!("expected deliver, got {other:?}"),
        }
    }

    /// req: REQ-RELAY-008
    #[tokio::test]
    async fn only_allowed_orgs_are_served() {
        let state = new_state(Duration::from_secs(10));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        let served = state.clone();
        tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
        let (ok_root, other_root) = (DeviceKey::generate(), DeviceKey::generate());
        let (ka, kb) = (DeviceKey::generate(), DeviceKey::generate());
        // Written in upper case: the list is case-insensitive.
        let list = format!("  {}, bogus\n", org_id(&ok_root).to_ascii_uppercase());
        set_allowed_orgs(&state, parse_allowed_orgs(&list));

        let mut a = login(&url, &ka).await;
        join(&mut a, &ok_root, &ka).await;

        // A valid proof for another org is still refused, and the device cannot route there.
        let mut b = login(&url, &kb).await;
        announce(&mut b, &org_id(&other_root), proof(&other_root, &kb, true)).await;
        expect_error(next_frame(&mut b).await, "org-not-allowed");
        send_frame(
            &mut b,
            &Frame::Broadcast {
                org: org_id(&other_root),
                body: vec![1],
            },
        )
        .await;
        expect_error(next_frame(&mut b).await, "not-a-member");

        // Lifting the restriction serves the org again.
        set_allowed_orgs(&state, parse_allowed_orgs(""));
        join(&mut b, &other_root, &kb).await;
    }

    /// req: REQ-RELAY-009
    #[tokio::test]
    async fn open_mode_ignores_the_list_but_keeps_revocation_storage() {
        use crate::state::{BoxFuture, OpenOrgs, RevocationRecord, StateStore, refresh_allowlist};
        /// A configured store with an empty list (approves nobody) that keeps revocations.
        struct Closed;
        impl StateStore for Closed {
            fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
                Box::pin(async { Ok(Some(HashSet::new())) })
            }
            fn keeps_revocations(&self) -> bool {
                true
            }
            fn save_revocation<'a>(
                &'a self,
                _rec: &'a RevocationRecord,
            ) -> BoxFuture<'a, Result<(), String>> {
                Box::pin(async { Ok(()) })
            }
        }
        let state = new_state(Duration::from_secs(10));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        let served = state.clone();
        tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
        let (root, key) = (DeviceKey::generate(), DeviceKey::generate());

        // Closed store: nobody is approved.
        refresh_allowlist(&state, &Closed).await.unwrap();
        let mut a = login(&url, &key).await;
        announce(&mut a, &org_id(&root), proof(&root, &key, true)).await;
        expect_error(next_frame(&mut a).await, "org-not-allowed");

        // Open mode over the same store: the list is not consulted, persistence is kept.
        let open = OpenOrgs(Arc::new(Closed));
        assert!(open.keeps_revocations());
        assert!(!open.refreshes());
        refresh_allowlist(&state, &open).await.unwrap();
        join(&mut a, &root, &key).await;
    }

    /// req: REQ-RELAY-008
    #[tokio::test]
    async fn removing_an_org_from_the_list_evicts_its_devices() {
        let state = new_state(Duration::from_secs(10));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        let served = state.clone();
        tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
        let (root, other) = (DeviceKey::generate(), DeviceKey::generate());
        let key = DeviceKey::generate();
        let both = format!("{} {}", org_id(&root), org_id(&other));
        set_allowed_orgs(&state, parse_allowed_orgs(&both));
        let mut a = login(&url, &key).await;
        join(&mut a, &root, &key).await;
        join(&mut a, &other, &key).await;

        set_allowed_orgs(&state, parse_allowed_orgs(&org_id(&other)));
        expect_error(next_frame(&mut a).await, "org-not-allowed");
        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org_id(&root),
                body: vec![1],
            },
        )
        .await;
        expect_error(next_frame(&mut a).await, "not-a-member");
        // The other org keeps working.
        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org_id(&other),
                body: vec![1],
            },
        )
        .await;
    }

    #[test]
    fn allowed_org_lists_parse() {
        assert_eq!(parse_allowed_orgs(""), None);
        assert_eq!(parse_allowed_orgs(" , \n"), None);
        let set = parse_allowed_orgs("AB,cd ef\n12").unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.contains("ab") && set.contains("12"));
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn frames_before_authentication_are_refused() {
        let url = start(Duration::from_secs(10)).await;
        let key = DeviceKey::generate();
        let mut ws = connect(&url).await;
        let broadcast = Frame::Broadcast {
            org: "org".into(),
            body: vec![1],
        };
        send_frame(&mut ws, &broadcast).await;
        expect_error(next_frame(&mut ws).await, "unauthenticated");

        send_frame(&mut ws, &hello_frame(&key)).await;
        assert!(matches!(
            next_frame(&mut ws).await,
            Some(Frame::Challenge { .. })
        ));
        send_frame(&mut ws, &broadcast).await; // challenged but not yet authenticated
        expect_error(next_frame(&mut ws).await, "unauthenticated");
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn wrong_key_or_garbage_signature_fails() {
        let url = start(Duration::from_secs(10)).await;
        let (claimed, other) = (DeviceKey::generate(), DeviceKey::generate());

        // Signs the right message with a different key.
        let mut ws = connect(&url).await;
        send_frame(&mut ws, &hello_frame(&claimed)).await;
        let Some(Frame::Challenge { nonce }) = next_frame(&mut ws).await else {
            panic!()
        };
        send_frame(&mut ws, &auth_frame(&other, &nonce)).await;
        expect_error(next_frame(&mut ws).await, "auth-failed");
        assert!(next_frame(&mut ws).await.is_none(), "connection is closed");

        // Not even hex.
        let mut ws = connect(&url).await;
        send_frame(&mut ws, &hello_frame(&claimed)).await;
        let Some(Frame::Challenge { .. }) = next_frame(&mut ws).await else {
            panic!()
        };
        send_frame(
            &mut ws,
            &Frame::Auth {
                signature: "zz".into(),
            },
        )
        .await;
        expect_error(next_frame(&mut ws).await, "auth-failed");

        // A valid signature for an old nonce does not work on a new connection.
        let mut first = connect(&url).await;
        send_frame(&mut first, &hello_frame(&claimed)).await;
        let Some(Frame::Challenge { nonce: old }) = next_frame(&mut first).await else {
            panic!()
        };
        let mut second = connect(&url).await;
        send_frame(&mut second, &hello_frame(&claimed)).await;
        let Some(Frame::Challenge { nonce: new }) = next_frame(&mut second).await else {
            panic!()
        };
        assert_ne!(old, new);
        send_frame(&mut second, &auth_frame(&claimed, &old)).await;
        expect_error(next_frame(&mut second).await, "auth-failed");
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn device_id_must_be_a_public_key() {
        let url = start(Duration::from_secs(10)).await;
        let mut ws = connect(&url).await;
        send_frame(
            &mut ws,
            &Frame::Hello {
                version: PROTOCOL_VERSION,
                device: "alice".into(),
            },
        )
        .await;
        expect_error(next_frame(&mut ws).await, "bad-device");
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn protocol_versions_outside_the_supported_range_are_refused() {
        let url = start(Duration::from_secs(10)).await;
        for version in [MIN_PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
            let mut ws = connect(&url).await;
            let key = DeviceKey::generate();
            send_frame(
                &mut ws,
                &Frame::Hello {
                    version,
                    device: key.device_id().to_hex(),
                },
            )
            .await;
            expect_error(next_frame(&mut ws).await, "version");
        }
        // The oldest supported version still gets its challenge.
        let mut ws = connect(&url).await;
        let key = DeviceKey::generate();
        send_frame(
            &mut ws,
            &Frame::Hello {
                version: MIN_PROTOCOL_VERSION,
                device: key.device_id().to_hex(),
            },
        )
        .await;
        assert!(matches!(
            next_frame(&mut ws).await,
            Some(Frame::Challenge { .. })
        ));
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn unauthenticated_connections_time_out() {
        let url = start(Duration::from_millis(200)).await;
        let mut ws = connect(&url).await;
        expect_error(next_frame(&mut ws).await, "auth-timeout");
        assert!(next_frame(&mut ws).await.is_none());
    }

    /// req: REQ-RELAY-001
    #[tokio::test]
    async fn reconnecting_replaces_the_old_connection_without_dropping_the_new_one() {
        let url = start(Duration::from_secs(10)).await;
        let (root, ka, kb) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let mut old = login(&url, &ka).await;
        join(&mut old, &root, &ka).await;
        let mut new = login(&url, &ka).await;
        join(&mut new, &root, &ka).await;
        // The old connection is closed by the relay...
        assert!(next_frame(&mut old).await.is_none());
        // ...and its teardown did not unregister the new one.
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        send_frame(
            &mut b,
            &Frame::Broadcast {
                org: org_id(&root),
                body: b"x".to_vec(),
            },
        )
        .await;
        loop {
            match next_frame(&mut new).await {
                Some(Frame::Deliver { body, .. }) => {
                    assert_eq!(body, b"x");
                    break;
                }
                Some(Frame::Presence { .. }) => continue,
                other => panic!("expected deliver, got {other:?}"),
            }
        }
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn bad_proofs_are_refused_and_non_members_cannot_send() {
        let url = start(Duration::from_secs(10)).await;
        let (root, key) = (DeviceKey::generate(), DeviceKey::generate());
        let mut ws = login(&url, &key).await;
        let org = org_id(&root);
        // Garbage, a chain for another device, a self-made chain, a name as org ID.
        announce(&mut ws, &org, "zz".into()).await;
        expect_error(next_frame(&mut ws).await, "bad-proof");
        announce(&mut ws, &org, proof(&root, &DeviceKey::generate(), false)).await;
        expect_error(next_frame(&mut ws).await, "bad-proof");
        announce(&mut ws, &org, proof(&key, &key, true)).await;
        expect_error(next_frame(&mut ws).await, "bad-proof");
        announce(&mut ws, "my-org", proof(&root, &key, false)).await;
        expect_error(next_frame(&mut ws).await, "bad-org");
        for f in [
            Frame::Broadcast {
                org: org.clone(),
                body: vec![1],
            },
            Frame::SyncRequest {
                org: org.clone(),
                body: vec![1],
            },
            Frame::Direct {
                org: org.clone(),
                to: root.device_id().to_hex(),
                body: vec![1],
            },
        ] {
            send_frame(&mut ws, &f).await;
            expect_error(next_frame(&mut ws).await, "not-a-member");
        }
    }

    /// req: REQ-INV-004
    #[tokio::test]
    async fn a_signed_revocation_removes_the_device_and_keeps_it_out() {
        use kith_core::membership::Revocation;
        let url = start(Duration::from_secs(10)).await;
        let (root, admin_key, member_key, own_key) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let (org, rid) = (org_id(&root), root.device_id());
        let admin_chain = CertChain(vec![MembershipCert::issue(
            &root,
            rid,
            admin_key.device_id(),
            true,
            1,
        )]);
        let member_cert = MembershipCert::issue(&root, rid, member_key.device_id(), false, 1);
        // The member's own device is certified through the member.
        let own_chain = CertChain(vec![
            member_cert.clone(),
            MembershipCert::issue_own(&member_key, rid, own_key.device_id(), 2),
        ]);
        let mut admin = login(&url, &admin_key).await;
        join(&mut admin, &root, &admin_key).await;
        let mut member = login(&url, &member_key).await;
        join(&mut member, &root, &member_key).await;
        assert!(matches!(
            next_frame(&mut admin).await,
            Some(Frame::Presence { .. })
        ));
        let mut own = login(&url, &own_key).await;
        announce(&mut own, &org, own_chain.to_hex()).await;
        assert!(matches!(
            next_frame(&mut own).await,
            Some(Frame::Presence { .. })
        ));
        assert!(matches!(
            next_frame(&mut admin).await,
            Some(Frame::Presence { .. })
        ));
        assert!(matches!(
            next_frame(&mut member).await,
            Some(Frame::Presence { .. })
        ));

        let announce_with = |notices: Vec<String>| Frame::Announce {
            orgs: vec![Membership {
                org: org.clone(),
                proof: admin_chain.to_hex(),
                always_on: false,
                revoked: notices,
            }],
        };
        // A notice from a plain member is refused and changes nothing.
        let member_chain = CertChain(vec![member_cert.clone()]);
        let forged = Revocation::issue(&member_key, member_chain, rid, admin_key.device_id(), 3);
        send_frame(&mut admin, &announce_with(vec![forged.to_hex()])).await;
        expect_error(next_frame(&mut admin).await, "bad-revocation");
        // (The announce itself still goes through and refreshes presence.)
        while !matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 3)
        {
        }

        // The admin's notice removes the member and the device certified through it.
        let notice = Revocation::issue(
            &admin_key,
            admin_chain.clone(),
            rid,
            member_key.device_id(),
            4,
        );
        send_frame(&mut admin, &announce_with(vec![notice.to_hex()])).await;
        expect_error_after_presence(&mut member, "revoked").await;
        expect_error_after_presence(&mut own, "revoked").await;
        loop {
            match next_frame(&mut admin).await {
                Some(Frame::Presence { online, .. }) if online.len() == 1 => break,
                Some(Frame::Presence { .. }) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
        // They are out of the org: nothing they send is routed.
        send_frame(
            &mut member,
            &Frame::Broadcast {
                org: org.clone(),
                body: b"x".to_vec(),
            },
        )
        .await;
        expect_error_after_presence(&mut member, "not-a-member").await;
        // Announcing again is refused, with or without the notice being repeated.
        announce(&mut member, &org, member_cert_hex(&member_cert)).await;
        expect_error_after_presence(&mut member, "revoked").await;
        announce(&mut own, &org, own_chain.to_hex()).await;
        expect_error_after_presence(&mut own, "revoked").await;
        // A fresh device of the admin still joins.
        let mut other = login(&url, &DeviceKey::generate()).await;
        send_frame(&mut other, &announce_with(vec![])).await;
        expect_error(next_frame(&mut other).await, "bad-proof");
    }

    /// req: REQ-INV-004
    #[tokio::test]
    async fn stored_revocations_survive_a_relay_restart() {
        use crate::state::{
            BoxFuture, RevocationRecord, StateStore, load_revocations, spawn_revocation_writer,
        };
        use kith_core::membership::Revocation;
        #[derive(Default)]
        struct Mem(Mutex<Vec<RevocationRecord>>);
        impl StateStore for Mem {
            fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
                Box::pin(async { Ok(None) })
            }
            fn keeps_revocations(&self) -> bool {
                true
            }
            fn save_revocation<'a>(
                &'a self,
                rec: &'a RevocationRecord,
            ) -> BoxFuture<'a, Result<(), String>> {
                self.0.lock().unwrap().push(rec.clone());
                Box::pin(async { Ok(()) })
            }
        }
        let serve = |state: Shared| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
            url
        };
        let (root, admin_key, member_key) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let (org, rid) = (org_id(&root), root.device_id());
        let admin_chain = CertChain(vec![MembershipCert::issue(
            &root,
            rid,
            admin_key.device_id(),
            true,
            1,
        )]);
        let member_cert = MembershipCert::issue(&root, rid, member_key.device_id(), false, 1);
        let notice = Revocation::issue(
            &admin_key,
            admin_chain.clone(),
            rid,
            member_key.device_id(),
            4,
        );

        // Relay 1 accepts the notice and hands it to the store.
        let store = Arc::new(Mem::default());
        let state1 = new_state(Duration::from_secs(10));
        spawn_revocation_writer(&state1, store.clone());
        let url1 = serve(state1).await;
        let mut admin = login(&url1, &admin_key).await;
        send_frame(
            &mut admin,
            &Frame::Announce {
                orgs: vec![Membership {
                    org: org.clone(),
                    proof: admin_chain.to_hex(),
                    always_on: false,
                    revoked: vec![notice.to_hex()],
                }],
            },
        )
        .await;
        for _ in 0..50 {
            if !store.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let records = store.0.lock().unwrap().clone();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].device, member_key.device_id().to_hex());

        // A new relay that loads the records refuses the device without any admin online.
        let state2 = new_state(Duration::from_secs(10));
        assert_eq!(load_revocations(&state2, &records), 1);
        // A forged record is skipped.
        let bogus = RevocationRecord {
            notice: "00".into(),
            ..records[0].clone()
        };
        assert_eq!(load_revocations(&state2, &[bogus]), 0);
        let url2 = serve(state2).await;
        let mut member = login(&url2, &member_key).await;
        announce(&mut member, &org, member_cert_hex(&member_cert)).await;
        expect_error(next_frame(&mut member).await, "revoked");
    }

    /// req: REQ-ID-002
    #[tokio::test]
    async fn a_claim_can_be_addressed_to_one_certified_member() {
        let url = start(Duration::from_secs(10)).await;
        let (root, member_key, new_key) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let org = org_id(&root);
        let mut member = login(&url, &member_key).await;
        announce(&mut member, &org, proof(&root, &member_key, false)).await;
        assert!(matches!(
            next_frame(&mut member).await,
            Some(Frame::Presence { .. })
        ));
        let mut new = login(&url, &new_key).await;
        announce(&mut new, &org, String::new()).await;
        let claim = |to: String| Frame::InviteClaim {
            org: org.clone(),
            token: "t".into(),
            body: b"claim".to_vec(),
            to: Some(to),
        };
        // No admin is online, but the claim reaches the named (non-admin) member.
        send_frame(&mut new, &claim(member_key.device_id().to_hex())).await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
        );
        assert!(
            matches!(next_frame(&mut member).await, Some(Frame::ClaimDeliver { body, .. }) if body == b"claim")
        );
        // A pending or unknown device is not a target.
        send_frame(&mut new, &claim(new_key.device_id().to_hex())).await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
        );
        send_frame(&mut new, &claim("00".repeat(32))).await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
        );
    }

    /// req: REQ-RELAY-004
    /// req: REQ-INV-002
    #[tokio::test]
    async fn a_pending_device_can_only_claim_and_receive_until_it_proves_membership() {
        let url = start(Duration::from_secs(10)).await;
        let (root, admin_key, new_key) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let org = org_id(&root);
        let mut admin = login(&url, &admin_key).await;
        announce(&mut admin, &org, proof(&root, &admin_key, true)).await;
        assert!(
            matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 1)
        );

        // The new device announces without a proof: pending, no presence.
        let mut new = login(&url, &new_key).await;
        announce(&mut new, &org, String::new()).await;
        send_frame(
            &mut new,
            &Frame::Broadcast {
                org: org.clone(),
                body: vec![1],
            },
        )
        .await;
        expect_error(next_frame(&mut new).await, "not-a-member");
        // Its claim reaches the admin.
        send_frame(
            &mut new,
            &Frame::InviteClaim {
                org: org.clone(),
                token: "t".into(),
                body: b"claim".to_vec(),
                to: None,
            },
        )
        .await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
        );
        match next_frame(&mut admin).await {
            Some(Frame::ClaimDeliver { from, body, .. }) => {
                assert_eq!(from, new_key.device_id().to_hex());
                assert_eq!(body, b"claim");
            }
            other => panic!("expected the claim, got {other:?}"),
        }
        // The admin's direct (the Welcome) reaches the pending device.
        send_frame(
            &mut admin,
            &Frame::Direct {
                org: org.clone(),
                to: new_key.device_id().to_hex(),
                body: b"welcome".to_vec(),
            },
        )
        .await;
        assert!(
            matches!(next_frame(&mut admin).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
        );
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Deliver { body, .. }) if body == b"welcome")
        );
        // With its certificate it becomes a member and shows up in presence.
        announce(&mut new, &org, proof(&root, &new_key, false)).await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Presence { online, .. }) if online.len() == 2)
        );
        assert!(
            matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 2)
        );
    }

    /// req: REQ-INV-002
    #[tokio::test]
    async fn claims_without_an_online_admin_are_dropped() {
        let url = start(Duration::from_secs(10)).await;
        let (root, member_key, new_key) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let org = org_id(&root);
        let mut member = login(&url, &member_key).await;
        join(&mut member, &root, &member_key).await;
        let mut new = login(&url, &new_key).await;
        announce(&mut new, &org, String::new()).await;
        send_frame(
            &mut new,
            &Frame::InviteClaim {
                org,
                token: "t".into(),
                body: vec![1],
                to: None,
            },
        )
        .await;
        assert!(
            matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
        );
    }

    // ---- abuse limits (REQ-RELAY-006) ----

    async fn start_with(limits: Limits) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app(new_state_with(Duration::from_secs(10), limits)),
            )
            .await
            .unwrap();
        });
        url
    }

    /// Frames that arrive within `wait`; `None` at the end if the relay closed.
    async fn drain(ws: &mut Ws, wait: Duration) -> (Vec<Frame>, bool) {
        let mut out = vec![];
        loop {
            match tokio::time::timeout(wait, ws.next()).await {
                Err(_) => return (out, false),
                Ok(Some(Ok(tungstenite::Message::Binary(b)))) => out.push(decode(&b).unwrap()),
                Ok(Some(Ok(tungstenite::Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                    return (out, true);
                }
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    fn count(frames: &[Frame], pick: impl Fn(&Frame) -> bool) -> usize {
        frames.iter().filter(|f| pick(f)).count()
    }

    fn rate_limited(f: &Frame) -> bool {
        matches!(f, Frame::Error { code, .. } if code == "rate-limited")
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn frames_beyond_a_devices_burst_are_dropped() {
        let url = start_with(Limits {
            device_frames_per_sec: 1.0,
            device_burst: 10.0,
            ..Limits::default()
        })
        .await;
        let (root, ka, kb) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        for _ in 0..20 {
            send_frame(
                &mut a,
                &Frame::Broadcast {
                    org: org_id(&root),
                    body: vec![1],
                },
            )
            .await;
        }
        let (frames, closed) = drain(&mut a, Duration::from_millis(500)).await;
        assert!(!closed);
        let receipts = count(&frames, |f| matches!(f, Frame::Receipt { .. }));
        // 3 of the burst went to hello, auth and announce.
        // (A slow machine may refill a token or two while the frames are processed.)
        assert!((7..=9).contains(&receipts), "{receipts}: {frames:?}");
        assert!(count(&frames, rate_limited) >= 1);
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn persistent_abusers_are_disconnected() {
        let url = start_with(Limits {
            device_frames_per_sec: 1.0,
            device_burst: 5.0,
            max_refused: 10,
            ..Limits::default()
        })
        .await;
        let (root, ka) = (DeviceKey::generate(), DeviceKey::generate());
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        for _ in 0..40 {
            if a.send(tungstenite::Message::Binary(
                encode(&Frame::Broadcast {
                    org: org_id(&root),
                    body: vec![1],
                })
                .unwrap()
                .into(),
            ))
            .await
            .is_err()
            {
                break;
            }
        }
        let (_, closed) = drain(&mut a, Duration::from_secs(2)).await;
        assert!(closed, "the relay closes the connection");
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn an_org_limit_covers_all_its_devices() {
        let url = start_with(Limits {
            org_frames_per_sec: 0.5,
            ..Limits::default()
        })
        .await;
        let (root, ka, kb) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        for _ in 0..5 {
            send_frame(
                &mut a,
                &Frame::Broadcast {
                    org: org_id(&root),
                    body: vec![1],
                },
            )
            .await;
            send_frame(
                &mut b,
                &Frame::Broadcast {
                    org: org_id(&root),
                    body: vec![2],
                },
            )
            .await;
        }
        let (fa, _) = drain(&mut a, Duration::from_millis(500)).await;
        let (fb, _) = drain(&mut b, Duration::from_millis(500)).await;
        let receipts = count(&fa, |f| matches!(f, Frame::Receipt { .. }))
            + count(&fb, |f| matches!(f, Frame::Receipt { .. }));
        assert!(
            (1..=2).contains(&receipts),
            "a burst of 2 x 0.5 frames per second, shared: {receipts}"
        );
        assert!(count(&fa, rate_limited) + count(&fb, rate_limited) >= 8);
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn connections_beyond_the_maximum_are_refused() {
        let url = start_with(Limits {
            max_connections: 1,
            ..Limits::default()
        })
        .await;
        let first = connect(&url).await;
        assert!(connect_async(&url).await.is_err(), "HTTP 503");
        drop(first);
        // The slot frees up once the first connection is gone.
        for _ in 0..50 {
            if connect_async(&url).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the slot was never freed");
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn oversized_messages_close_the_connection() {
        let url = start_with(Limits {
            max_message_bytes: 1000,
            ..Limits::default()
        })
        .await;
        let mut ws = connect(&url).await;
        let _ = ws
            .send(tungstenite::Message::Binary(vec![b'x'; 5000].into()))
            .await;
        let (_, closed) = drain(&mut ws, Duration::from_secs(2)).await;
        assert!(closed);
    }

    // ---- revocation rules (ADR 0018) ----

    fn ann(org: &str, proof: String, revoked: Vec<String>) -> Frame {
        Frame::Announce {
            orgs: vec![Membership {
                org: org.into(),
                proof,
                always_on: false,
                revoked,
            }],
        }
    }

    /// req: REQ-INV-004
    #[tokio::test]
    async fn only_the_root_removes_admins_and_revoked_admins_revoke_nobody() {
        let url = start(Duration::from_secs(10)).await;
        let root = DeviceKey::generate();
        let rid = root.device_id();
        let org = org_id(&root);
        let (ka, kb, km) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let chain_a = CertChain(vec![MembershipCert::issue(
            &root,
            rid,
            ka.device_id(),
            true,
            1,
        )]);
        let chain_b = CertChain(vec![MembershipCert::issue(
            &root,
            rid,
            kb.device_id(),
            true,
            1,
        )]);
        let mut b = login(&url, &kb).await;
        send_frame(&mut b, &ann(&org, chain_b.to_hex(), vec![])).await;
        assert!(matches!(
            next_frame(&mut b).await,
            Some(Frame::Presence { .. })
        ));
        // An admin's notice against another admin does not remove it.
        let mut a = login(&url, &ka).await;
        let a_on_b = Revocation::issue(&ka, chain_a.clone(), rid, kb.device_id(), 2);
        send_frame(&mut a, &ann(&org, chain_a.to_hex(), vec![a_on_b.to_hex()])).await;
        let mut b2 = login(&url, &kb).await;
        send_frame(&mut b2, &ann(&org, chain_b.to_hex(), vec![])).await;
        assert!(matches!(
            next_frame(&mut b2).await,
            Some(Frame::Presence { .. })
        ));
        // The root removes A.
        let root_on_a = Revocation::issue_by_root(&root, ka.device_id(), 3);
        send_frame(
            &mut b2,
            &ann(&org, chain_b.to_hex(), vec![root_on_a.to_hex()]),
        )
        .await;
        // Applied once B hears that A left (announces of different connections
        // are not ordered otherwise).
        assert!(matches!(
            next_frame(&mut b2).await,
            Some(Frame::Presence { .. })
        ));
        let mut a2 = login(&url, &ka).await;
        send_frame(&mut a2, &ann(&org, chain_a.to_hex(), vec![])).await;
        expect_error(next_frame(&mut a2).await, "revoked");
        // A's notices no longer count, even sent by someone else's announce.
        let mut m = login(&url, &km).await;
        join(&mut m, &root, &km).await;
        let a_on_m = Revocation::issue(&ka, chain_a, rid, km.device_id(), 4);
        send_frame(&mut b2, &ann(&org, chain_b.to_hex(), vec![a_on_m.to_hex()])).await;
        expect_error_after_presence(&mut b2, "bad-revocation").await;
        // A revoked device does not come back as a newcomer either.
        let mut a3 = login(&url, &ka).await;
        send_frame(&mut a3, &ann(&org, String::new(), vec![])).await;
        expect_error(next_frame(&mut a3).await, "revoked");
    }

    /// req: REQ-INV-004
    #[tokio::test]
    async fn only_admins_send_revocation_notices() {
        let url = start(Duration::from_secs(10)).await;
        let root = DeviceKey::generate();
        let org = org_id(&root);
        let (km, kx) = (DeviceKey::generate(), DeviceKey::generate());
        let mut m = login(&url, &km).await;
        join(&mut m, &root, &km).await;
        // A member hands on a valid root notice: refused, nothing changes.
        let notice = Revocation::issue_by_root(&root, kx.device_id(), 1);
        send_frame(
            &mut m,
            &ann(&org, proof(&root, &km, false), vec![notice.to_hex()]),
        )
        .await;
        expect_error(next_frame(&mut m).await, "bad-revocation");
        let mut x = login(&url, &kx).await;
        join(&mut x, &root, &kx).await;
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn claims_arrive_as_claims_and_org_ids_have_one_spelling() {
        let url = start(Duration::from_secs(10)).await;
        let root = DeviceKey::generate();
        let (km, kx) = (DeviceKey::generate(), DeviceKey::generate());
        let mut m = login(&url, &km).await;
        join(&mut m, &root, &km).await;
        let mut x = login(&url, &kx).await;
        // Upper case is the same org.
        announce(&mut x, &org_id(&root).to_uppercase(), String::new()).await;
        send_frame(
            &mut x,
            &Frame::InviteClaim {
                org: org_id(&root).to_uppercase(),
                token: String::new(),
                body: b"anything".to_vec(),
                to: Some(km.device_id().to_hex()),
            },
        )
        .await;
        match next_frame(&mut m).await {
            Some(Frame::ClaimDeliver { org, body, .. }) => {
                assert_eq!(body, b"anything");
                assert_eq!(org, org_id(&root));
            }
            other => panic!("{other:?}"),
        }
    }

    /// req: REQ-INV-004
    #[test]
    fn stored_notices_of_a_removed_admin_count_only_from_before_its_removal() {
        let root = DeviceKey::generate();
        let rid = root.device_id();
        let org = org_id(&root);
        let (ka, m_old, m_new) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let chain_a = CertChain(vec![MembershipCert::issue(
            &root,
            rid,
            ka.device_id(),
            true,
            1,
        )]);
        let rec = |r: &Revocation| state::RevocationRecord {
            org: org.to_uppercase(),
            device: r.device.to_hex(),
            notice: r.to_hex(),
        };
        let before = Revocation::issue(&ka, chain_a.clone(), rid, m_old.device_id(), 5);
        let after = Revocation::issue(&ka, chain_a, rid, m_new.device_id(), 20);
        let removal = Revocation::issue_by_root(&root, ka.device_id(), 10);
        // Stored order does not matter: the root's notice is applied first.
        let shared = new_state(Duration::from_secs(10));
        state::load_revocations(&shared, &[rec(&before), rec(&after), rec(&removal)]);
        let r = shared.lock().unwrap();
        let set = r.revoked.get(&org).expect("canonical org");
        assert!(set.contains_key(&m_old.device_id().to_hex()));
        assert!(!set.contains_key(&m_new.device_id().to_hex()));
        assert!(set[&ka.device_id().to_hex()].by_root);
    }

    // ---- resource limits (REQ-RELAY-006, ADR 0019) ----

    /// A relay on `state`, with connection info (as the binary runs it).
    async fn start_state(state: Shared) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        url
    }

    fn claim(org: &str) -> Frame {
        Frame::InviteClaim {
            org: org.into(),
            token: "t".into(),
            body: b"claim".to_vec(),
            to: None,
        }
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn pending_devices_do_not_use_up_the_orgs_budget() {
        let url = start_with(Limits {
            org_frames_per_sec: 2.0,
            pending_frames_per_sec: 0.5,
            ..Limits::default()
        })
        .await;
        let (root, ka, kb, kp) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let org = org_id(&root);
        let mut a = login(&url, &ka).await;
        announce(&mut a, &org, proof(&root, &ka, true)).await;
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        let mut p = login(&url, &kp).await;
        announce(&mut p, &org, String::new()).await;
        for _ in 0..10 {
            send_frame(&mut p, &claim(&org)).await;
        }
        let (frames, _) = drain(&mut p, Duration::from_millis(300)).await;
        assert_eq!(
            count(&frames, |f| matches!(f, Frame::Receipt { .. })),
            1,
            "a burst of 2 x 0.5 claims: {frames:?}"
        );
        assert!(count(&frames, rate_limited) >= 8);
        // The members' budget is untouched.
        send_frame(
            &mut b,
            &Frame::Broadcast {
                org: org.clone(),
                body: vec![1],
            },
        )
        .await;
        let (frames, _) = drain(&mut b, Duration::from_millis(300)).await;
        assert_eq!(
            count(&frames, |f| matches!(f, Frame::Receipt { .. })),
            1,
            "{frames:?}"
        );
        assert_eq!(count(&frames, rate_limited), 0);
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn outboxes_have_a_frame_and_byte_budget() {
        let big = |n: usize| Frame::Deliver {
            org: "o".into(),
            from: "f".into(),
            body: vec![0; n],
        };
        // One frame always fits; more only within the byte budget.
        let (tx, mut rx) = Tx::new(2000);
        assert!(queue(&tx, big(5000)));
        assert!(!queue(&tx, big(10)));
        let (_, n) = rx.try_recv().unwrap();
        tx.queued.fetch_sub(n, Ordering::Relaxed);
        assert!(queue(&tx, big(1000)));
        assert!(!queue(&tx, big(1000)), "over the byte budget");
        // And within the frame budget.
        let (tx, _rx) = Tx::new(usize::MAX);
        for _ in 0..MAX_QUEUED_FRAMES {
            assert!(queue(&tx, big(0)));
        }
        assert!(!queue(&tx, big(0)), "over the frame budget");
    }

    /// req: REQ-RELAY-006
    #[test]
    fn receipts_leave_out_devices_whose_outbox_is_full() {
        let state = new_state(Duration::from_secs(10));
        let mut r = state.lock().unwrap();
        // Two devices; nobody reads `stuck`'s outbox, as with a device that stopped reading.
        let (stuck, _rx1) = Tx::new(usize::MAX);
        let (fine, _rx2) = Tx::new(usize::MAX);
        while queue(&stuck, error("x", String::new())) {}
        r.conns.insert("stuck".into(), Conn { id: 1, tx: stuck });
        r.conns.insert("fine".into(), Conn { id: 2, tx: fine });
        let to = ["stuck".to_string(), "fine".to_string(), "gone".to_string()];
        assert_eq!(fan_out(&r, &to, || error("y", String::new())), ["fine"]);
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn silent_connections_are_closed_and_answering_ones_kept() {
        let url = start_with(Limits {
            idle_timeout: Duration::from_millis(300),
            ..Limits::default()
        })
        .await;
        let (root, ka, kb) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        let mut b = login(&url, &kb).await;
        join(&mut b, &root, &kb).await;
        // b keeps reading, so its client answers the relay's pings.
        let until = Instant::now() + Duration::from_millis(1200);
        while Instant::now() < until {
            if let Ok(Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_))) =
                tokio::time::timeout(Duration::from_millis(100), b.next()).await
            {
                panic!("a device that answers pings stays");
            }
        }
        // a read nothing all that time, so it never answered: closed. (Its client may
        // fail answering the queued pings before it reads the `idle-timeout` error.)
        let (frames, closed) = drain(&mut a, Duration::from_secs(2)).await;
        assert!(closed, "{frames:?}");
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn connections_per_client_address_are_limited() {
        let state = new_state_with(
            Duration::from_secs(10),
            Limits {
                max_connections_per_ip: 2,
                ..Limits::default()
            },
        );
        let url = start_state(state).await;
        let first = connect(&url).await;
        let _second = connect(&url).await;
        assert!(connect_async(&url).await.is_err(), "HTTP 429");
        drop(first);
        for _ in 0..50 {
            if connect_async(&url).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the slot was never freed");
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn behind_a_proxy_the_forwarded_address_counts() {
        use tungstenite::client::IntoClientRequest;
        let state = new_state_with(
            Duration::from_secs(10),
            Limits {
                max_connections_per_ip: 1,
                client_ip_header: Some("x-forwarded-for".into()),
                ..Limits::default()
            },
        );
        let url = start_state(state).await;
        let from = |ip: &str| {
            let mut req = url.as_str().into_client_request().unwrap();
            req.headers_mut().insert(
                "x-forwarded-for",
                format!("10.0.0.9, {ip}").parse().unwrap(),
            );
            req
        };
        let _a = connect_async(from("192.0.2.1")).await.unwrap();
        let _b = connect_async(from("192.0.2.2")).await.unwrap();
        assert!(connect_async(from("192.0.2.1")).await.is_err());
    }

    #[test]
    fn client_addresses_use_the_proxys_entry_and_group_ipv6_by_64() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let mut h = HeaderMap::new();
        h.append(
            "x-forwarded-for",
            "203.0.113.5, 198.51.100.7".parse().unwrap(),
        );
        let ip = |h: &HeaderMap, name| client_ip(peer, h, name).unwrap().to_string();
        assert_eq!(ip(&h, None), "127.0.0.1");
        assert_eq!(ip(&h, Some("x-forwarded-for")), "198.51.100.7");
        assert_eq!(ip(&HeaderMap::new(), Some("x-forwarded-for")), "127.0.0.1");
        h.insert("x-forwarded-for", "2001:db8:1:2:3:4:5:6".parse().unwrap());
        assert_eq!(ip(&h, Some("x-forwarded-for")), "2001:db8:1:2::");
        h.insert("x-forwarded-for", "garbage".parse().unwrap());
        assert_eq!(ip(&h, Some("x-forwarded-for")), "127.0.0.1");
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn orgs_per_announce_and_per_device_are_capped() {
        let url = start(Duration::from_secs(10)).await;
        let key = DeviceKey::generate();
        let mut ws = login(&url, &key).await;
        let pending = |n: usize| Frame::Announce {
            orgs: (0..n)
                .map(|_| Membership {
                    org: org_id(&DeviceKey::generate()),
                    proof: String::new(),
                    always_on: false,
                    revoked: vec![],
                })
                .collect(),
        };
        send_frame(&mut ws, &pending(MAX_ORGS_PER_ANNOUNCE + 1)).await;
        expect_error(next_frame(&mut ws).await, "too-many-orgs");
        send_frame(&mut ws, &pending(MAX_ORGS_PER_DEVICE)).await;
        send_frame(&mut ws, &pending(1)).await;
        expect_error(next_frame(&mut ws).await, "too-many-orgs");
    }

    #[test]
    fn the_relay_keeps_a_bounded_number_of_revocations() {
        let state = new_state(Duration::from_secs(10));
        let root = DeviceKey::generate();
        let org = org_id(&root);
        let notice =
            |dev: &DeviceKey| Revocation::issue_by_root(&root, dev.device_id(), 1).to_hex();
        let mut r = state.lock().unwrap();
        let rev = |n: &str| verify_notice(&root.device_id(), n).unwrap();
        let first = notice(&DeviceKey::generate());
        assert_eq!(
            remember_verified(&mut r, &org, &rev(&first), &first, false),
            Ok(true)
        );
        r.revoked_total = MAX_REVOKED_TOTAL;
        let next = notice(&DeviceKey::generate());
        assert!(remember_verified(&mut r, &org, &rev(&next), &next, false).is_err());
        // Known devices are still recognised.
        assert_eq!(
            remember_verified(&mut r, &org, &rev(&first), &first, false),
            Ok(false)
        );
    }

    /// req: REQ-RELAY-006
    #[tokio::test]
    async fn rate_buckets_of_orgs_without_online_devices_are_forgotten() {
        let state = new_state(Duration::from_secs(10));
        let url = start_state(state.clone()).await;
        let (root, ka, kp) = (
            DeviceKey::generate(),
            DeviceKey::generate(),
            DeviceKey::generate(),
        );
        let org = org_id(&root);
        let mut a = login(&url, &ka).await;
        join(&mut a, &root, &ka).await;
        let mut p = login(&url, &kp).await;
        announce(&mut p, &org, String::new()).await;
        send_frame(&mut p, &claim(&org)).await;
        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org.clone(),
                body: vec![1],
            },
        )
        .await;
        let _ = next_frame(&mut p).await;
        while !matches!(next_frame(&mut a).await, Some(Frame::Receipt { .. })) {}
        {
            let r = state.lock().unwrap();
            assert!(r.org_buckets.contains_key(&org) && r.pending_buckets.contains_key(&org));
        }
        drop(a);
        drop(p);
        for _ in 0..100 {
            {
                let r = state.lock().unwrap();
                if r.org_buckets.is_empty() && r.pending_buckets.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the buckets were kept");
    }
}
