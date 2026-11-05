//! kith relay: WebSocket front end around `kith_relay::RoutingTable`.
//!
//! Configuration (environment):
//! - `KITH_RELAY_ADDR`: listen address, default `0.0.0.0:8080`
//! - `KITH_RELAY_AUTH_TIMEOUT_SECS`: seconds a connection has to authenticate, default `10`
//! - abuse limits (REQ-RELAY-006), see [`Limits::from_env`]
//! - `KITH_RELAY_ALLOWED_ORGS`: org IDs (hex root public keys, separated by commas or
//!   whitespace) this relay serves (REQ-RELAY-008). Unset or empty: every org is served.
//! - `RUST_LOG`: log filter, default `info`
//!
//! Connection: `hello` -> relay `challenge` -> `auth` (signature over
//! [`kith_protocol::auth_message`]). Every other frame is refused until the device
//! has proven it owns its key. Then `announce` lists orgs with membership proofs
//! (certificate chains, ADR 0005), checked against the org ID, which is the org's
//! root public key (REQ-RELAY-004). A device announcing an org without a proof is
//! *pending*: it may only send `invite-claim` (routed to the org's online admins)
//! and receive `direct` messages.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use kith_core::membership::{CertChain, Revocation};
use kith_core::{DeviceId, verify_signature};
use kith_protocol::{Frame, PROTOCOL_VERSION, auth_message, decode, encode};
use kith_relay::{Role, Route, RoutingTable};
use tokio::sync::mpsc;

/// What a connection's writer task is asked to do.
enum Out {
    Frame(Frame),
    /// Close the connection (for example because the device reconnected).
    Close,
}

type Tx = mpsc::UnboundedSender<Out>;

fn send(tx: &Tx, frame: Frame) {
    let _ = tx.send(Out::Frame(frame));
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
        }
    }
}

impl Limits {
    /// Defaults, overridden by `KITH_RELAY_DEVICE_FRAMES_PER_SEC`,
    /// `KITH_RELAY_DEVICE_BURST`, `KITH_RELAY_DEVICE_BYTES_PER_SEC`,
    /// `KITH_RELAY_ORG_FRAMES_PER_SEC`, `KITH_RELAY_MAX_CONNECTIONS`,
    /// `KITH_RELAY_MAX_MESSAGE_BYTES`, `KITH_RELAY_MAX_REFUSED`.
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

    fn take(&mut self, n: f64) -> bool {
        let now = Instant::now();
        self.tokens =
            (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate).min(self.burst);
        self.last = now;
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
    /// Revoked devices per org (REQ-INV-004). RAM only; admins repeat them on announce.
    revoked: HashMap<String, HashSet<String>>,
    /// Certificate chains of announced devices: device -> org -> chain, so a
    /// revocation also removes devices certified through the revoked one.
    proofs: HashMap<String, HashMap<String, CertChain>>,
    /// Orgs this relay serves (REQ-RELAY-008); `None` serves every org.
    allowed_orgs: Option<HashSet<String>>,
}

/// Revoked devices remembered per org at most (memory bound).
const MAX_REVOKED_PER_ORG: usize = 10_000;
/// Revocation notices read from one announce at most.
const MAX_NOTICES_PER_ANNOUNCE: usize = 256;

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
        revoked: HashMap::new(),
        proofs: HashMap::new(),
        allowed_orgs: None,
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

/// Restrict the relay to `orgs` (`None` serves every org). It applies to announces made
/// afterwards; devices already announced for a removed org stay until they reconnect.
pub fn set_allowed_orgs(state: &Shared, orgs: Option<HashSet<String>>) {
    state.lock().unwrap().allowed_orgs = orgs;
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

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Shared>) -> Response {
    let (open, limits) = {
        let r = state.lock().unwrap();
        (r.open.clone(), r.limits.clone())
    };
    if open.fetch_add(1, Ordering::Relaxed) >= limits.max_connections {
        open.fetch_sub(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
    }
    let guard = OpenGuard(open);
    ws.max_message_size(limits.max_message_bytes)
        .max_frame_size(limits.max_message_bytes)
        .on_upgrade(move |socket| async move {
            let _guard = guard;
            connection(socket, state, limits).await
        })
}

async fn connection(mut socket: WebSocket, state: Shared, limits: Limits) {
    let mut frames = Bucket::new(limits.device_frames_per_sec, limits.device_burst);
    let mut bytes = Bucket::new(
        limits.device_bytes_per_sec,
        limits.device_bytes_per_sec * 4.0,
    );
    let mut refused = 0u32;
    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
    let (conn_id, auth_timeout) = {
        let r = state.lock().unwrap();
        (r.next_conn.fetch_add(1, Ordering::Relaxed), r.auth_timeout)
    };
    let mut session = Session::New;
    let deadline = tokio::time::sleep(auth_timeout);
    tokio::pin!(deadline);

    loop {
        let authed = matches!(session, Session::Authed(_));
        tokio::select! {
            out = rx.recv() => match out {
                Some(Out::Frame(f)) => {
                    let Ok(bytes) = encode(&f) else { continue };
                    if socket.send(Message::Binary(bytes.into())).await.is_err() { break; }
                }
                Some(Out::Close) | None => break,
            },
            () = &mut deadline, if !authed => {
                tracing::debug!("authentication timed out");
                send_now(&mut socket, error("auth-timeout", "authenticate within the time limit".into())).await;
                break;
            }
            msg = socket.recv() => {
                let Some(Ok(msg)) = msg else { break };
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
                        send_now(&mut socket, error("rate-limited", "too many frames; closing".into())).await;
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
                        if handle(frame, &mut session, conn_id, &tx, &state) == Flow::Close {
                            // Flush the queued error frame, then hang up.
                            while let Ok(Out::Frame(f)) = rx.try_recv() {
                                send_now(&mut socket, f).await;
                            }
                            break;
                        }
                    }
                    Err(e) => send(&tx, error("bad-frame", e.to_string())),
                }
            }
        }
    }

    // Say goodbye properly so clients see a clean close, not a reset.
    let _ = socket.send(Message::Close(None)).await;

    if let Session::Authed(d) = session {
        let mut r = state.lock().unwrap();
        // A newer connection of the same device may have replaced this one; only
        // clean up if this connection still owns the device's slot.
        if r.conns.get(&d).is_some_and(|c| c.id == conn_id) {
            r.table.disconnect(&d);
            r.proofs.remove(&d);
            r.conns.remove(&d);
            tracing::debug!(device = %d, "disconnected");
        }
    }
}

async fn send_now(socket: &mut WebSocket, frame: Frame) {
    if let Ok(bytes) = encode(&frame) {
        let _ = socket.send(Message::Binary(bytes.into())).await;
    }
}

#[derive(PartialEq, Eq)]
enum Flow {
    Continue,
    Close,
}

fn handle(frame: Frame, session: &mut Session, conn_id: u64, tx: &Tx, state: &Shared) -> Flow {
    let mut r = state.lock().unwrap();
    // Handshake first: nothing else is accepted before the device is authenticated.
    match (&*session, frame) {
        (Session::New, Frame::Hello { version, device }) => {
            if version != PROTOCOL_VERSION {
                send(
                    tx,
                    error("version", format!("relay speaks v{PROTOCOL_VERSION}")),
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
        (Session::Challenged { device, nonce }, Frame::Auth { signature }) => {
            let sig = hex::decode(&signature)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok());
            let device_hex = device.to_hex();
            let ok = sig.is_some_and(|s| {
                verify_signature(device, &auth_message(&device_hex, nonce), &s).is_ok()
            });
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
            // A reconnecting device replaces its old connection, which is closed.
            if let Some(old) = r.conns.insert(
                device_hex.clone(),
                Conn {
                    id: conn_id,
                    tx: tx.clone(),
                },
            ) {
                let _ = old.tx.send(Out::Close);
            }
            tracing::debug!(device = %device_hex, "authenticated");
            *session = Session::Authed(device_hex);
            Flow::Continue
        }
        (Session::Authed(_), Frame::Hello { .. } | Frame::Auth { .. }) => {
            send(tx, error("unsupported", "already authenticated".into()));
            Flow::Continue
        }
        (Session::Authed(d), frame) => {
            let d = d.clone();
            route(frame, &d, tx, &mut r);
            Flow::Continue
        }
        (Session::New, _) => {
            send(tx, error("unauthenticated", "send hello first".into()));
            Flow::Continue
        }
        (Session::Challenged { .. }, _) => {
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

/// The role a membership proof gives `device` in `org` (REQ-RELAY-004). An empty
/// proof means "joining": pending.
fn check_membership(
    org: &str,
    device: &str,
    proof: &str,
    revoked: Option<&HashSet<String>>,
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
    if revoked.is_some_and(|set| chain.touches(|d| set.contains(&d.to_hex()))) {
        return Err("device was revoked");
    }
    let role = if proven.admin {
        Role::Admin
    } else {
        Role::Member
    };
    Ok((role, Some(chain)))
}

/// Verify and remember the revocation notices of an announce, then remove every
/// online device of `org` they affect (the revoked ones and devices certified
/// through them). Bad notices are ignored with an error to `tx`.
fn apply_revocations(r: &mut Relay, org: &str, notices: &[String], tx: &Tx) {
    let Ok(org_key) = DeviceId::from_hex(org) else {
        return;
    };
    let mut added = false;
    for n in notices.iter().take(MAX_NOTICES_PER_ANNOUNCE) {
        let rev = match Revocation::from_hex(n).and_then(|rev| rev.verify(&org_key).map(|_| rev)) {
            Ok(rev) => rev,
            Err(e) => {
                send(tx, error("bad-revocation", format!("{org}: {e}")));
                continue;
            }
        };
        let set = r.revoked.entry(org.to_string()).or_default();
        if set.len() < MAX_REVOKED_PER_ORG || set.contains(&rev.device.to_hex()) {
            added |= set.insert(rev.device.to_hex());
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
            set.contains(dev)
                || r.proofs
                    .get(dev)
                    .and_then(|m| m.get(org))
                    .is_some_and(|c| c.touches(|d| set.contains(&d.to_hex())))
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
    let online = r.table.online(org);
    fan_out(r, &online, || Frame::Presence {
        org: org.to_string(),
        online: online.clone(),
    });
}

/// Take one routed frame from `org`'s bucket.
fn org_allows(r: &mut Relay, org: &str) -> bool {
    let rate = r.limits.org_frames_per_sec;
    r.org_buckets
        .entry(org.to_string())
        .or_insert_with(|| Bucket::new(rate, rate * 2.0))
        .take(1.0)
}

fn route(frame: Frame, d: &str, tx: &Tx, r: &mut Relay) {
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
        && r.table.role(&org, d).is_some()
        && !org_allows(r, &org)
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
        Frame::Announce { orgs } => {
            for m in orgs {
                if let Some(allowed) = &r.allowed_orgs
                    && !allowed.contains(&m.org.to_ascii_lowercase())
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
                // Notices first: they may revoke this very device.
                // (Pending devices, without a proof, do not feed the list.)
                if !m.revoked.is_empty() && !m.proof.is_empty() {
                    apply_revocations(r, &m.org, &m.revoked, tx);
                }
                let (role, chain) =
                    match check_membership(&m.org, d, &m.proof, r.revoked.get(&m.org)) {
                        Ok(x) => x,
                        Err(why) => {
                            let code = if why == "device was revoked" {
                                "revoked"
                            } else {
                                "bad-proof"
                            };
                            send(tx, error(code, format!("{}: {why}", m.org)));
                            continue;
                        }
                    };
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
            deliver(r, route, tx, org, d, body);
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
        other => send(tx, error("unsupported", format!("{other:?}"))),
    }
}

fn deliver(r: &Relay, route: Route, tx: &Tx, org: String, from: &str, body: Vec<u8>) {
    let delivered = match route {
        Route::To(devs) => {
            fan_out(r, &devs, || Frame::Deliver {
                org: org.clone(),
                from: from.into(),
                body: body.clone(),
            });
            devs
        }
        Route::Dropped => vec![],
    };
    send(tx, Frame::Receipt { delivered });
}

fn fan_out(r: &Relay, to: &[String], make: impl Fn() -> Frame) {
    for d in to {
        if let Some(conn) = r.conns.get(d) {
            send(&conn.tx, make());
        }
    }
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
        expect_error(next_frame(&mut ws).await, "bad-proof");
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
            matches!(next_frame(&mut member).await, Some(Frame::Deliver { body, .. }) if body == b"claim")
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
            Some(Frame::Deliver { from, body, .. }) => {
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
}
