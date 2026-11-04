//! Foreign-language bindings (UniFFI) for Swift and Kotlin.
//!
//! Keep this layer thin: convert types and errors, call into `kith-client`.
//! Anything with logic belongs in the Rust crates so every platform behaves
//! identically.

#![allow(missing_docs)] // UniFFI generates items

use std::sync::{Arc, Mutex};

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use kith_store::SqliteStore;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KithError {
    #[error("{msg}")]
    Failed { msg: String },
}

macro_rules! into_kith_error {
    ($($t:ty),*) => {$(
        impl From<$t> for KithError {
            fn from(e: $t) -> Self {
                KithError::Failed { msg: e.to_string() }
            }
        }
    )*};
}
into_kith_error!(
    kith_client::ClientError,
    kith_client::IdError,
    kith_client::StoreError
);

type DynStore = Box<dyn Store + Send>;

fn seed_from(secret_key: Vec<u8>) -> Result<DeviceKey, KithError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|v: Vec<u8>| KithError::Failed {
            msg: format!("secret key must be 32 bytes, got {}", v.len()),
        })?;
    Ok(DeviceKey::from_secret_bytes(&seed))
}

/// A new random 32-byte device secret key. Save it in the platform's secure
/// storage before first use, then pass it to `KithClient.open`.
#[uniffi::export]
pub fn generate_secret_key() -> Vec<u8> {
    DeviceKey::generate().secret_bytes().to_vec()
}

/// Library version.
#[uniffi::export]
pub fn kith_version() -> String {
    kith_client::kith_core_version().to_string()
}

/// A change as seen by apps.
#[derive(uniffi::Record)]
pub struct ChangeInfo {
    pub change_id: String,
    pub object_id: String,
    pub object_type: String,
    pub author: String,
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
}

impl From<kith_client::Change> for ChangeInfo {
    fn from(c: kith_client::Change) -> Self {
        Self {
            change_id: c.change_id.to_hex(),
            object_id: c.body.object_id.to_hex(),
            object_type: c.body.object_type.0,
            author: c.author.to_hex(),
            timestamp_ms: c.body.timestamp_ms,
            payload: c.body.payload,
        }
    }
}

/// Client handle exposed to Swift/Kotlin.
#[derive(uniffi::Object)]
pub struct KithClient {
    inner: Mutex<Client<DynStore>>,
}

#[uniffi::export]
impl KithClient {
    /// New client with a fresh device key and in-memory store.
    ///
    /// The identity is lost when the client is dropped unless the app saves
    /// `secret_key()` and restores it with `with_secret_key`.
    /// For persistence use `open`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Client::new(
                DeviceKey::generate(),
                Box::new(MemoryStore::new()),
            )),
        }
    }

    /// New client that restores a device identity from its 32-byte secret key
    /// (as returned by `secret_key()`), with an in-memory store.
    #[uniffi::constructor]
    pub fn with_secret_key(secret_key: Vec<u8>) -> Result<Self, KithError> {
        Ok(Self {
            inner: Mutex::new(Client::new(
                seed_from(secret_key)?,
                Box::new(MemoryStore::new()),
            )),
        })
    }

    /// Persistent client: SQLite database at `db_path` (created if missing)
    /// and the device identity from `secret_key`. Reopening the same path with
    /// the same key restores all data and the identity.
    #[uniffi::constructor]
    pub fn open(db_path: String, secret_key: Vec<u8>) -> Result<Self, KithError> {
        let store = SqliteStore::open(db_path)?;
        Ok(Self {
            inner: Mutex::new(Client::new(seed_from(secret_key)?, Box::new(store))),
        })
    }

    /// The 32-byte secret key of this device. Store it only in the platform's
    /// secure storage (Keychain, Android Keystore); anyone who has it can
    /// sign as this device.
    pub fn secret_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().signer().secret_bytes().to_vec()
    }

    pub fn device_id(&self) -> String {
        self.inner.lock().unwrap().device_id().to_hex()
    }

    pub fn create(&self, object_type: String, payload: Vec<u8>) -> Result<ChangeInfo, KithError> {
        let c = self
            .inner
            .lock()
            .unwrap()
            .create(ObjectType::new(object_type), payload)?;
        Ok(c.into())
    }

    pub fn edit(&self, object_id: String, payload: Vec<u8>) -> Result<ChangeInfo, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        Ok(self.inner.lock().unwrap().edit(oid, payload)?.into())
    }

    pub fn history(&self, object_id: String) -> Result<Vec<ChangeInfo>, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        let h = self.inner.lock().unwrap().history(&oid)?;
        Ok(h.into_iter().map(Into::into).collect())
    }
}

/// What happened when a frame from the relay was handled.
#[derive(uniffi::Enum)]
pub enum RelayEvent {
    /// A peer's change was valid and is stored. `is_new` is false if it was already known.
    Received {
        org: String,
        from: String,
        object_id: String,
        change_id: String,
        is_new: bool,
    },
    /// A peer's change was refused (bad hash or signature); nothing was stored.
    Rejected {
        org: String,
        from: String,
        reason: String,
    },
    /// Devices currently online in an organization.
    Presence { org: String, online: Vec<String> },
    /// Which devices a broadcast of ours reached.
    Receipt { delivered: Vec<String> },
    /// The relay refused something (for example `auth-failed`, after which it closes).
    RelayError { code: String, message: String },
}

/// Result of [`RelaySession::receive`].
#[derive(uniffi::Record)]
pub struct SessionOutput {
    /// Frames to send to the relay right away, in order.
    pub replies: Vec<Vec<u8>>,
    /// What the frame meant for the app, if anything.
    pub event: Option<RelayEvent>,
}

/// Live sync with one organization through a relay, without owning the socket.
///
/// The app opens a WebSocket (`URLSessionWebSocketTask`, OkHttp, ...) to the
/// relay's `/v1/ws`, sends [`hello`](Self::hello) when it opens, passes every
/// binary message to [`receive`](Self::receive) and sends the returned
/// `replies`. After `create`/`edit`, send [`broadcast`](Self::broadcast).
/// Only online devices are reached; message bodies are not encrypted yet.
#[derive(uniffi::Object)]
pub struct RelaySession {
    client: Arc<KithClient>,
    org: String,
}

#[uniffi::export]
impl KithClient {
    /// Start live sync with `org`. See [`RelaySession`].
    pub fn relay_session(self: Arc<Self>, org: String) -> Arc<RelaySession> {
        Arc::new(RelaySession { client: self, org })
    }
}

#[uniffi::export]
impl RelaySession {
    /// The first frame to send once the WebSocket is open.
    pub fn hello(&self) -> Result<Vec<u8>, KithError> {
        let c = self.client.inner.lock().unwrap();
        encode_frame(&kith_client::hello_frame(c.signer()))
    }

    /// Handle one binary message from the relay: answers the handshake, validates
    /// and stores peers' changes. A bad change from a peer is an
    /// `Event::Rejected`, not an error; an error means the frame itself was
    /// malformed or local storage failed.
    pub fn receive(&self, frame: Vec<u8>) -> Result<SessionOutput, KithError> {
        let frame =
            kith_protocol::decode(&frame).map_err(|e| KithError::Failed { msg: e.to_string() })?;
        let mut c = self.client.inner.lock().unwrap();
        if let Some(replies) = kith_client::handshake_reply(c.signer(), &self.org, &frame) {
            return Ok(SessionOutput {
                replies: replies.iter().map(encode_frame).collect::<Result<_, _>>()?,
                event: None,
            });
        }
        Ok(SessionOutput {
            replies: vec![],
            event: relay_event(c.handle_frame(frame)?),
        })
    }

    /// The frame that tells the other online devices about a local change
    /// (as returned by `create`/`edit`).
    pub fn broadcast(&self, change_id: String) -> Result<Vec<u8>, KithError> {
        let id = kith_client::ChangeId::from_hex(&change_id)?;
        let c = self.client.inner.lock().unwrap();
        let change = c.store().get(&id)?.ok_or_else(|| KithError::Failed {
            msg: format!("unknown change {change_id}"),
        })?;
        encode_frame(&kith_client::broadcast_frame(&self.org, &change))
    }
}

fn encode_frame(f: &kith_protocol::Frame) -> Result<Vec<u8>, KithError> {
    kith_protocol::encode(f).map_err(|e| KithError::Failed { msg: e.to_string() })
}

fn relay_event(ev: kith_client::Event) -> Option<RelayEvent> {
    use kith_client::Event;
    Some(match ev {
        Event::Received {
            org,
            from,
            change,
            is_new,
        } => RelayEvent::Received {
            org,
            from,
            object_id: change.body.object_id.to_hex(),
            change_id: change.change_id.to_hex(),
            is_new,
        },
        Event::Rejected { org, from, reason } => RelayEvent::Rejected { org, from, reason },
        Event::Presence { org, online } => RelayEvent::Presence { org, online },
        Event::Receipt { delivered } => RelayEvent::Receipt { delivered },
        Event::RelayError { code, message } => RelayEvent::RelayError { code, message },
        Event::Ignored => return None,
    })
}

impl Default for KithClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// req: REQ-PLAT-002
    #[test]
    fn restored_key_keeps_device_identity() {
        let a = KithClient::new();
        let b = KithClient::with_secret_key(a.secret_key()).unwrap();
        assert_eq!(a.device_id(), b.device_id());
        let c = b.create("note".into(), b"x".to_vec()).unwrap();
        assert_eq!(c.author, a.device_id());
        assert_ne!(KithClient::new().device_id(), a.device_id());
    }

    /// req: REQ-PLAT-002
    /// req: REQ-STORE-001
    #[test]
    fn open_persists_data_and_identity() {
        let dir = std::env::temp_dir().join(format!(
            "kith-ffi-{}",
            generate_secret_key()[0..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kith.db").to_string_lossy().into_owned();
        let key = generate_secret_key();

        let first = KithClient::open(path.clone(), key.clone()).unwrap();
        let created = first.create("note".into(), b"v1".to_vec()).unwrap();
        first
            .edit(created.object_id.clone(), b"v2".to_vec())
            .unwrap();
        let device = first.device_id();
        drop(first);

        let second = KithClient::open(path, key).unwrap();
        assert_eq!(second.device_id(), device);
        assert_eq!(second.history(created.object_id).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_rejects_bad_key_and_bad_path() {
        assert!(KithClient::open("/nonexistent-dir/x.db".into(), generate_secret_key()).is_err());
        assert!(KithClient::open(":memory:".into(), vec![1; 5]).is_err());
    }

    /// What the relay does for a broadcast: wrap the body in a deliver frame.
    fn relay_deliver(from: &KithClient, broadcast: &[u8]) -> Vec<u8> {
        let kith_protocol::Frame::Broadcast { org, body } =
            kith_protocol::decode(broadcast).unwrap()
        else {
            panic!("broadcast frame expected")
        };
        kith_protocol::encode(&kith_protocol::Frame::Deliver {
            org,
            from: from.device_id(),
            body,
        })
        .unwrap()
    }

    /// req: REQ-SYNC-004
    #[test]
    fn sessions_exchange_changes_through_frames() {
        let a = Arc::new(KithClient::new());
        let b = Arc::new(KithClient::new());
        let (sa, sb) = (
            a.clone().relay_session("org".into()),
            b.clone().relay_session("org".into()),
        );

        // Handshake: hello -> (relay) challenge -> auth + announce.
        let hello = kith_protocol::decode(&sa.hello().unwrap()).unwrap();
        assert!(matches!(hello, kith_protocol::Frame::Hello { .. }));
        let challenge =
            kith_protocol::encode(&kith_protocol::Frame::Challenge { nonce: "ab".into() }).unwrap();
        let out = sa.receive(challenge).unwrap();
        assert!(out.event.is_none());
        let frames: Vec<_> = out
            .replies
            .iter()
            .map(|f| kith_protocol::decode(f).unwrap())
            .collect();
        assert!(matches!(frames[0], kith_protocol::Frame::Auth { .. }));
        assert!(matches!(frames[1], kith_protocol::Frame::Announce { .. }));

        // A change made on a reaches b.
        let created = a.create("note".into(), b"v1".to_vec()).unwrap();
        let broadcast = sa.broadcast(created.change_id.clone()).unwrap();
        let out = sb.receive(relay_deliver(&a, &broadcast)).unwrap();
        match out.event {
            Some(RelayEvent::Received {
                object_id,
                change_id,
                is_new,
                from,
                ..
            }) => {
                assert_eq!(object_id, created.object_id);
                assert_eq!(change_id, created.change_id);
                assert_eq!(from, a.device_id());
                assert!(is_new);
            }
            _ => panic!("expected a received event"),
        }
        assert_eq!(b.history(created.object_id).unwrap().len(), 1);
        assert!(sa.broadcast("00".repeat(32)).is_err(), "unknown change");
    }

    /// req: REQ-SYNC-004
    #[test]
    fn tampered_and_garbage_frames_do_not_store_anything() {
        let a = Arc::new(KithClient::new());
        let b = Arc::new(KithClient::new());
        let (sa, sb) = (
            a.clone().relay_session("org".into()),
            b.clone().relay_session("org".into()),
        );
        let created = a.create("note".into(), b"v1".to_vec()).unwrap();
        let broadcast = sa.broadcast(created.change_id).unwrap();
        // Flip a payload byte inside the encoded change (the last bytes are the payload).
        let kith_protocol::Frame::Broadcast { org, mut body } =
            kith_protocol::decode(&broadcast).unwrap()
        else {
            panic!()
        };
        *body.last_mut().unwrap() ^= 1;
        let tampered = kith_protocol::encode(&kith_protocol::Frame::Deliver {
            org,
            from: a.device_id(),
            body,
        })
        .unwrap();
        let out = sb.receive(tampered).unwrap();
        assert!(matches!(out.event, Some(RelayEvent::Rejected { .. })));
        assert!(sb.receive(b"not a frame".to_vec()).is_err());
        assert!(b.history(created.object_id).unwrap().is_empty());
    }

    /// req: REQ-PLAT-002
    #[test]
    fn rejects_wrong_length_secret_key() {
        assert!(KithClient::with_secret_key(vec![0; 31]).is_err());
        assert!(KithClient::with_secret_key(vec![0; 33]).is_err());
    }
}
