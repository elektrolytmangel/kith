//! kith relay: WebSocket front end around `kith_relay::RoutingTable`.
//!
//! Configuration (environment):
//! - `KITH_RELAY_ADDR`: listen address, default `0.0.0.0:8080`
//! - `KITH_RELAY_AUTH_TIMEOUT_SECS`: seconds a connection has to authenticate, default `10`
//! - `RUST_LOG`: log filter, default `info`
//!
//! Connection: `hello` -> relay `challenge` -> `auth` (signature over
//! [`kith_protocol::auth_message`]). Every other frame is refused until the device
//! has proven it owns its key. Membership-proof checks (the org root key) are
//! still TODO (REQ-RELAY-004); do not expose publicly yet.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use kith_core::{DeviceId, verify_signature};
use kith_protocol::{Frame, PROTOCOL_VERSION, auth_message, decode, encode};
use kith_relay::{Route, RoutingTable};
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

/// Relay state. Opaque outside this crate; create it with [`new_state`].
pub struct Relay {
    table: RoutingTable,
    conns: HashMap<String, Conn>,
    next_conn: AtomicU64,
    auth_timeout: Duration,
}

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

/// Fresh relay state. `auth_timeout` is how long a new connection has to authenticate.
pub fn new_state(auth_timeout: Duration) -> Shared {
    Arc::new(Mutex::new(Relay {
        table: RoutingTable::default(),
        conns: HashMap::new(),
        next_conn: AtomicU64::new(0),
        auth_timeout,
    }))
}

/// The relay's HTTP/WebSocket routes (`/healthz`, `/v1/ws`).
pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Shared>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| connection(socket, state))
}

async fn connection(mut socket: WebSocket, state: Shared) {
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
                let bytes = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                match decode(&bytes) {
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

fn route(frame: Frame, d: &str, tx: &Tx, r: &mut Relay) {
    match frame {
        Frame::Announce { orgs } => {
            for m in orgs {
                // TODO(REQ-RELAY-004): verify m.proof against the org root key.
                r.table.join(d, &m.org);
                let online = r.table.online(&m.org);
                fan_out(r, &online, || Frame::Presence {
                    org: m.org.clone(),
                    online: online.clone(),
                });
            }
        }
        Frame::Broadcast { org, body } => {
            let route = r.table.broadcast(&org, d);
            deliver(r, route, tx, org, d, body);
        }
        Frame::Direct { org, to, body } => {
            let route = r.table.direct(&org, &to);
            deliver(r, route, tx, org, d, body);
        }
        Frame::SyncRequest { org, body } => {
            let route = r.table.sync_partner(&org, d);
            deliver(r, route, tx, org, d, body);
        }
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

    async fn join(ws: &mut Ws, org: &str) {
        send_frame(
            ws,
            &Frame::Announce {
                orgs: vec![Membership {
                    org: org.into(),
                    proof: String::new(),
                }],
            },
        )
        .await;
        // Our own join is announced to us as presence.
        assert!(matches!(next_frame(ws).await, Some(Frame::Presence { .. })));
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
        let (ka, kb) = (DeviceKey::generate(), DeviceKey::generate());
        let mut a = login(&url, &ka).await;
        join(&mut a, "org").await;
        let mut b = login(&url, &kb).await;
        join(&mut b, "org").await;
        // a sees b come online.
        assert!(matches!(
            next_frame(&mut a).await,
            Some(Frame::Presence { .. })
        ));

        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: "org".into(),
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
        let (ka, kb) = (DeviceKey::generate(), DeviceKey::generate());
        let mut old = login(&url, &ka).await;
        join(&mut old, "org").await;
        let mut new = login(&url, &ka).await;
        join(&mut new, "org").await;
        // The old connection is closed by the relay...
        assert!(next_frame(&mut old).await.is_none());
        // ...and its teardown did not unregister the new one.
        let mut b = login(&url, &kb).await;
        join(&mut b, "org").await;
        send_frame(
            &mut b,
            &Frame::Broadcast {
                org: "org".into(),
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
}
