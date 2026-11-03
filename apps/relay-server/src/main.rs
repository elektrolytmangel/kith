//! Standalone kith relay: WebSocket front end around `kith_relay::RoutingTable`.
//!
//! Configuration (environment):
//! - `KITH_RELAY_ADDR`: listen address, default `0.0.0.0:8080`
//! - `RUST_LOG`: log filter, default `info`
//!
//! Status: phase 2 skeleton. Device authentication (challenge/response) and
//! membership-proof checks are TODO (REQ-RELAY-004); do not expose publicly yet.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
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
use kith_protocol::{Frame, PROTOCOL_VERSION, decode, encode};
use kith_relay::{Route, RoutingTable};
use tokio::sync::mpsc;

type Tx = mpsc::UnboundedSender<Frame>;

#[derive(Default)]
struct Relay {
    table: RoutingTable,
    conns: HashMap<String, Tx>,
}

type Shared = Arc<Mutex<Relay>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr = std::env::var("KITH_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let state: Shared = Arc::default();
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!(%addr, version = kith_protocol::PROTOCOL_VERSION, "kith relay listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Shared>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| connection(socket, state))
}

async fn connection(mut socket: WebSocket, state: Shared) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
    let mut device: Option<String> = None;

    loop {
        tokio::select! {
            Some(out) = rx.recv() => {
                let Ok(bytes) = encode(&out) else { continue };
                if socket.send(Message::Binary(bytes.into())).await.is_err() { break; }
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
                    Ok(frame) => handle(frame, &mut device, &tx, &state),
                    Err(e) => { let _ = tx.send(error("bad-frame", e.to_string())); }
                }
            }
        }
    }

    if let Some(d) = device {
        let mut r = state.lock().unwrap();
        r.table.disconnect(&d);
        r.conns.remove(&d);
        tracing::debug!(device = %d, "disconnected");
    }
}

fn handle(frame: Frame, device: &mut Option<String>, tx: &Tx, state: &Shared) {
    let mut r = state.lock().unwrap();
    match (frame, device.as_deref()) {
        (Frame::Hello { version, device: d }, None) => {
            if version != PROTOCOL_VERSION {
                let _ = tx.send(error(
                    "version",
                    format!("relay speaks v{PROTOCOL_VERSION}"),
                ));
                return;
            }
            // TODO(REQ-RELAY-004): send Challenge, verify Auth signature before registering.
            r.conns.insert(d.clone(), tx.clone());
            *device = Some(d);
        }
        (Frame::Announce { orgs }, Some(d)) => {
            for m in orgs {
                // TODO(REQ-RELAY-004): verify m.proof against the org root key.
                r.table.join(d, &m.org);
                let online = r.table.online(&m.org);
                fan_out(&r, &online, || Frame::Presence {
                    org: m.org.clone(),
                    online: online.clone(),
                });
            }
        }
        (Frame::Broadcast { org, body }, Some(d)) => {
            let route = r.table.broadcast(&org, d);
            deliver(&r, route, tx, org, d, body);
        }
        (Frame::Direct { org, to, body }, Some(d)) => {
            let route = r.table.direct(&org, &to);
            deliver(&r, route, tx, org, d, body);
        }
        (Frame::SyncRequest { org, body }, Some(d)) => {
            let route = r.table.sync_partner(&org, d);
            deliver(&r, route, tx, org, d, body);
        }
        (_, None) => {
            let _ = tx.send(error("unauthenticated", "send hello first".into()));
        }
        (other, Some(_)) => {
            let _ = tx.send(error("unsupported", format!("{other:?}")));
        }
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
    let _ = tx.send(Frame::Receipt { delivered });
}

fn fan_out(r: &Relay, to: &[String], make: impl Fn() -> Frame) {
    for d in to {
        if let Some(conn) = r.conns.get(d) {
            let _ = conn.send(make());
        }
    }
}

fn error(code: &str, message: String) -> Frame {
    Frame::Error {
        code: code.into(),
        message,
    }
}
