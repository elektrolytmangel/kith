//! Native network client for kith (not for wasm32: browsers use their own
//! WebSocket, see the web bindings).
//!
//! - [`RelayConnection`]: an authenticated WebSocket connection to a relay
//!   (`hello` → `challenge` → `auth`, REQ-RELAY-004).
//! - [`LiveClient`]: a [`Client`] that broadcasts each new change to the other
//!   online devices of an organization and validates what it receives
//!   (REQ-SYNC-004).
//!
//! Live updates only reach devices that are online. Catching up on changes
//! missed while offline is phase 3 (REQ-SYNC-001..003).
//!
//! TODO(phase 4, REQ-ENC-001): bodies are plaintext on the relay until MLS lands.

use futures_util::{SinkExt, StreamExt};
use kith_client::{
    Change, Client, ClientError, DeviceKey, Event, ObjectId, ObjectType, Signer, Store,
    announce_frame, auth_frame, broadcast_frame, hello_frame,
};
use kith_protocol::{Frame, decode, encode};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};

/// Network errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// WebSocket failure.
    #[error("connection: {0}")]
    Connection(#[from] tungstenite::Error),
    /// The relay sent something that is not a valid frame.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The relay closed the connection or refused us.
    #[error("relay refused: {0}")]
    Refused(String),
    /// Local client or storage failure.
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// An authenticated connection to a relay.
///
/// The relay sends no explicit "welcome": a bad signature makes it send an
/// `error` frame and close, which surfaces as [`NetError::Refused`] on the next
/// [`recv`](Self::recv).
pub struct RelayConnection {
    ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
}

impl RelayConnection {
    /// Connect to `url` (`ws://host:port/v1/ws`, or `wss://` with the `tls`
    /// feature) and prove ownership of `signer`'s device key.
    pub async fn connect(url: &str, signer: &dyn Signer) -> Result<Self, NetError> {
        let (ws, _) = connect_async(url).await?;
        let mut conn = Self { ws };
        conn.send(&hello_frame(signer)).await?;
        let nonce = match conn.recv().await? {
            Some(Frame::Challenge { nonce }) => nonce,
            Some(Frame::Error { code, message }) => {
                return Err(NetError::Refused(format!("{code}: {message}")));
            }
            other => {
                return Err(NetError::Protocol(format!(
                    "expected challenge, got {other:?}"
                )));
            }
        };
        // Sent without waiting: a failure closes the connection and shows up on the next recv.
        conn.send(&auth_frame(signer, &nonce)).await?;
        Ok(conn)
    }

    /// Send a frame.
    pub async fn send(&mut self, frame: &Frame) -> Result<(), NetError> {
        let bytes = encode(frame).map_err(|e| NetError::Protocol(e.to_string()))?;
        self.ws
            .send(tungstenite::Message::Binary(bytes.into()))
            .await?;
        Ok(())
    }

    /// Next frame from the relay, or `None` if it closed the connection cleanly.
    pub async fn recv(&mut self) -> Result<Option<Frame>, NetError> {
        loop {
            match self.ws.next().await {
                None | Some(Ok(tungstenite::Message::Close(_))) => return Ok(None),
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(tungstenite::Message::Binary(b))) => {
                    return decode(&b)
                        .map(Some)
                        .map_err(|e| NetError::Protocol(e.to_string()));
                }
                Some(Ok(tungstenite::Message::Text(t))) => {
                    return decode(t.as_bytes())
                        .map(Some)
                        .map_err(|e| NetError::Protocol(e.to_string()));
                }
                Some(Ok(_)) => continue, // ping/pong are answered by the library
            }
        }
    }

    /// Close the connection.
    pub async fn close(mut self) -> Result<(), NetError> {
        self.ws.close(None).await?;
        Ok(())
    }
}

/// A [`Client`] kept in sync with the other online devices of one organization.
pub struct LiveClient<S: Store> {
    client: Client<S, DeviceKey>,
    conn: RelayConnection,
    org: String,
}

impl<S: Store> LiveClient<S> {
    /// Connect to the relay and join `org`.
    pub async fn connect(
        url: &str,
        org: &str,
        client: Client<S, DeviceKey>,
    ) -> Result<Self, NetError> {
        let mut conn = RelayConnection::connect(url, client.signer()).await?;
        // TODO(REQ-RELAY-004, phase 5): a real membership proof.
        conn.send(&announce_frame(org, "")).await?;
        Ok(Self {
            client,
            conn,
            org: org.into(),
        })
    }

    /// The wrapped client (history, merging, device ID).
    pub fn client(&self) -> &Client<S, DeviceKey> {
        &self.client
    }

    /// Create an object and broadcast it to the online devices.
    pub async fn create(&mut self, ty: ObjectType, payload: Vec<u8>) -> Result<Change, NetError> {
        let change = self.client.create(ty, payload)?;
        self.conn.send(&broadcast_frame(&self.org, &change)).await?;
        Ok(change)
    }

    /// Edit an object and broadcast the change to the online devices.
    pub async fn edit(&mut self, object: ObjectId, payload: Vec<u8>) -> Result<Change, NetError> {
        let change = self.client.edit(object, payload)?;
        self.conn.send(&broadcast_frame(&self.org, &change)).await?;
        Ok(change)
    }

    /// Ask one online peer for the changes this device lacks, and offer it ours
    /// (catch-up, REQ-SYNC-001..003). Works from an empty store (a new device).
    /// The result arrives through [`next_event`](Self::next_event): `Event::Receipt`
    /// (empty `delivered`: no peer online, try later), then `Event::SyncReceived`.
    pub async fn catch_up(&mut self) -> Result<(), NetError> {
        let frame = self.client.sync_request_frame(&self.org)?;
        self.conn.send(&frame).await
    }

    /// Wait for the next frame from the relay and handle it. Peers' changes are
    /// validated and stored (`Event::Received`); bad ones are reported as
    /// `Event::Rejected`. Returns `Ok(None)` once the relay closes the
    /// connection; an error frame before that becomes [`NetError::Refused`].
    pub async fn next_event(&mut self) -> Result<Option<Event>, NetError> {
        match self.conn.recv().await? {
            None => Ok(None),
            Some(frame) => {
                let handled = self.client.handle_frame(frame)?;
                // Catch-up replies (what a peer asked for) go out right away.
                for reply in &handled.replies {
                    self.conn.send(reply).await?;
                }
                match handled.event {
                    Event::RelayError { code, message } if is_fatal(&code) => {
                        Err(NetError::Refused(format!("{code}: {message}")))
                    }
                    ev => Ok(Some(ev)),
                }
            }
        }
    }
}

/// Relay error codes after which the relay closes the connection.
fn is_fatal(code: &str) -> bool {
    matches!(
        code,
        "auth-failed" | "auth-timeout" | "bad-device" | "version"
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kith_client::MemoryStore;
    use kith_relay_server::{app, new_state};
    use tokio::time::timeout;

    use super::*;

    async fn relay() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app(new_state(Duration::from_secs(10))))
                .await
                .unwrap();
        });
        url
    }

    fn new_client() -> Client<MemoryStore, DeviceKey> {
        Client::new(DeviceKey::generate(), MemoryStore::new())
    }

    /// Wait for the next event matching `pick`, skipping presence and receipts.
    async fn until<S: Store, T>(
        l: &mut LiveClient<S>,
        mut pick: impl FnMut(Event) -> Option<T>,
    ) -> T {
        loop {
            let ev = timeout(Duration::from_secs(5), l.next_event())
                .await
                .expect("timed out")
                .unwrap()
                .expect("connection closed");
            if let Some(t) = pick(ev) {
                return t;
            }
        }
    }

    /// req: REQ-SYNC-004
    #[tokio::test]
    async fn changes_reach_the_other_online_device_and_back() {
        let url = relay().await;
        let mut a = LiveClient::connect(&url, "org", new_client())
            .await
            .unwrap();
        let mut b = LiveClient::connect(&url, "org", new_client())
            .await
            .unwrap();
        // Wait until both are registered: a sees b come online.
        until(&mut a, |e| match e {
            Event::Presence { online, .. } if online.len() == 2 => Some(()),
            _ => None,
        })
        .await;

        let created = a
            .create(ObjectType::new("note"), b"v1".to_vec())
            .await
            .unwrap();
        let oid = created.body.object_id;
        let got = until(&mut b, |e| match e {
            Event::Received { change, is_new, .. } => Some((change, is_new)),
            _ => None,
        })
        .await;
        assert_eq!(got.0.change_id, created.change_id);
        assert!(got.1);
        assert_eq!(b.client().history(&oid).unwrap().len(), 1);

        // And in the other direction, building on the received change.
        let edited = b.edit(oid, b"v2".to_vec()).await.unwrap();
        assert_eq!(edited.body.parents, vec![created.change_id]);
        until(&mut a, |e| {
            matches!(e, Event::Received { .. }).then_some(())
        })
        .await;
        assert_eq!(a.client().history(&oid).unwrap().len(), 2);
    }

    /// req: REQ-SYNC-003
    /// req: REQ-SYNC-001
    #[tokio::test]
    async fn a_new_device_catches_up_from_an_online_peer() {
        let url = relay().await;
        // `a` has history from before it went online.
        let mut seed = new_client();
        let created = seed
            .create(ObjectType::new("note"), b"v1".to_vec())
            .unwrap();
        let oid = created.body.object_id;
        seed.edit(oid, b"v2".to_vec()).unwrap();
        let mut a = LiveClient::connect(&url, "org", seed).await.unwrap();
        // `a` keeps answering requests in the background.
        let a_task = tokio::spawn(async move { while let Ok(Some(_)) = a.next_event().await {} });

        let mut b = LiveClient::connect(&url, "org", new_client())
            .await
            .unwrap();
        until(&mut b, |e| match e {
            Event::Presence { online, .. } if online.len() == 2 => Some(()),
            _ => None,
        })
        .await;
        b.catch_up().await.unwrap();
        let stored = until(&mut b, |e| match e {
            Event::SyncReceived { stored, .. } => Some(stored),
            _ => None,
        })
        .await;
        assert_eq!(stored, 2);
        assert_eq!(b.client().history(&oid).unwrap().len(), 2);
        a_task.abort();
    }

    /// req: REQ-SYNC-001
    #[tokio::test]
    async fn catch_up_with_nobody_online_is_reported_not_an_error() {
        let url = relay().await;
        let mut only = LiveClient::connect(&url, "org", new_client())
            .await
            .unwrap();
        until(&mut only, |e| {
            matches!(e, Event::Presence { .. }).then_some(())
        })
        .await;
        only.catch_up().await.unwrap();
        let delivered = until(&mut only, |e| match e {
            Event::Receipt { delivered } => Some(delivered),
            _ => None,
        })
        .await;
        assert!(delivered.is_empty());
    }

    /// req: REQ-SYNC-004
    #[tokio::test]
    async fn tampered_changes_are_rejected_and_not_stored() {
        let url = relay().await;
        let mut honest = LiveClient::connect(&url, "org", new_client())
            .await
            .unwrap();
        // A raw connection plays a malicious device that broadcasts a forged change.
        let evil_key = DeviceKey::generate();
        let mut evil = RelayConnection::connect(&url, &evil_key).await.unwrap();
        evil.send(&announce_frame("org", "")).await.unwrap();
        until(&mut honest, |e| match e {
            Event::Presence { online, .. } if online.len() == 2 => Some(()),
            _ => None,
        })
        .await;

        let mut source = Client::new(evil_key, MemoryStore::new());
        let mut forged = source
            .create(ObjectType::new("note"), b"ok".to_vec())
            .unwrap();
        forged.body.payload = b"tampered".to_vec();
        evil.send(&broadcast_frame("org", &forged)).await.unwrap();

        until(&mut honest, |e| {
            matches!(e, Event::Rejected { .. }).then_some(())
        })
        .await;
        assert!(!honest.client().store().contains(&forged.change_id).unwrap());
    }

    /// req: REQ-RELAY-004
    #[tokio::test]
    async fn a_relay_refusal_is_reported() {
        let url = relay().await;
        // Connect, then break the handshake by answering with a signature from another key.
        let claimed = DeviceKey::generate();
        let other = DeviceKey::generate();
        let (ws, _) = connect_async(&url).await.unwrap();
        let mut conn = RelayConnection { ws };
        conn.send(&hello_frame(&claimed)).await.unwrap();
        let Some(Frame::Challenge { nonce }) = conn.recv().await.unwrap() else {
            panic!("challenge expected")
        };
        conn.send(&auth_frame(&other, &nonce)).await.unwrap();
        match conn.recv().await.unwrap() {
            Some(Frame::Error { code, .. }) => assert_eq!(code, "auth-failed"),
            other => panic!("expected auth-failed, got {other:?}"),
        }
        assert!(conn.recv().await.unwrap().is_none());
    }
}
