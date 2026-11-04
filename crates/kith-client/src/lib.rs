//! High-level client SDK.
//!
//! This is the API apps program against, either directly (Rust desktop
//! apps, Tauri, headless always-on clients) or through the generated
//! bindings in `bindings/` (Swift, Kotlin, JavaScript/WASM).
//!
//! Extension points (see `docs/guides/adapting.md`):
//! - [`Store`]: bring your own storage backend.
//! - [`Signer`]: bring your own key storage (keychain, secure enclave).
//! - [`Transport`]: bring your own connection to the relay or peers.
//! - object types and payload formats are application-defined.

pub use kith_core::{
    Change, ChangeId, DeviceId, IdError, ObjectId, ObjectType, Signer, UnsignedChange,
};
pub use kith_crypto::DeviceKey;
#[cfg(feature = "automerge")]
pub use kith_merge::automerge_merger;
pub use kith_merge::{Materialized, MergeError, Merger};
pub use kith_store::{MemoryStore, Store, StoreError};

/// Library version (all kith crates are versioned together).
pub fn kith_core_version() -> &'static str {
    kith_core::VERSION
}

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Incoming change failed validation.
    #[error("rejected change: {0}")]
    Rejected(#[from] kith_core::ChangeError),
    /// Merging an object's history failed.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// Object does not exist locally.
    #[error("unknown object {0}")]
    UnknownObject(ObjectId),
}

/// Connection to the relay (or a direct peer). Implemented per platform:
/// tokio WebSocket on native, browser WebSocket on web.
pub trait Transport {
    /// Send an encoded protocol frame.
    fn send(&mut self, frame: kith_protocol::Frame) -> Result<(), String>;
}

/// The first frame to send after connecting to the relay.
pub fn hello_frame(signer: &dyn Signer) -> kith_protocol::Frame {
    kith_protocol::Frame::Hello {
        version: kith_protocol::PROTOCOL_VERSION,
        device: signer.device_id().to_hex(),
    }
}

/// The answer to the relay's [`kith_protocol::Frame::Challenge`]: a signature
/// proving this device owns its key (REQ-RELAY-004).
pub fn auth_frame(signer: &dyn Signer, nonce: &str) -> kith_protocol::Frame {
    let msg = kith_protocol::auth_message(&signer.device_id().to_hex(), nonce);
    kith_protocol::Frame::Auth {
        signature: hex_encode(&signer.sign(&msg)),
    }
}

/// The frames to send in answer to a relay's `challenge`: the signature that proves
/// device ownership, then the organization announcement. `None` for any other frame.
pub fn handshake_reply(
    signer: &dyn Signer,
    org: &str,
    frame: &kith_protocol::Frame,
) -> Option<Vec<kith_protocol::Frame>> {
    match frame {
        kith_protocol::Frame::Challenge { nonce } => {
            // Pipelined: a failed auth makes the relay send an error and close.
            Some(vec![auth_frame(signer, nonce), announce_frame(org, "")])
        }
        _ => None,
    }
}

/// Frame announcing membership of `org` after authenticating.
/// The relay does not check `proof` yet (REQ-RELAY-004, phase 5).
pub fn announce_frame(org: &str, proof: &str) -> kith_protocol::Frame {
    kith_protocol::Frame::Announce {
        orgs: vec![kith_protocol::Membership {
            org: org.into(),
            proof: proof.into(),
        }],
    }
}

/// Frame that broadcasts a new change to the other online devices of `org`
/// (REQ-SYNC-004). The body is the encoded change.
/// TODO(phase 4, REQ-ENC-001): encrypt the body with the org's MLS group; until
/// then it is **plaintext on the relay**.
pub fn broadcast_frame(org: &str, change: &Change) -> kith_protocol::Frame {
    kith_protocol::Frame::Broadcast {
        org: org.into(),
        body: kith_store::codec::encode_change(change),
    }
}

/// What a frame from the relay meant for this client.
#[derive(Debug)]
pub enum Event {
    /// A peer's change was valid and handled. `is_new` is false if it was already stored.
    Received {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// The change.
        change: Box<Change>,
        /// True if the change was not stored before.
        is_new: bool,
    },
    /// A peer's change was refused (undecodable, bad hash or signature). Nothing was stored.
    Rejected {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// Why.
        reason: String,
    },
    /// Devices currently online in an org.
    Presence {
        /// Organization.
        org: String,
        /// Online devices (hex).
        online: Vec<String>,
    },
    /// Which devices a broadcast of ours reached.
    Receipt {
        /// Devices that received it.
        delivered: Vec<String>,
    },
    /// The relay refused something.
    RelayError {
        /// Machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// A frame this client has nothing to do with.
    Ignored,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A device's view of the organizations it belongs to.
pub struct Client<S: Store, K: Signer = DeviceKey> {
    key: K,
    store: S,
}

impl<S: Store, K: Signer> Client<S, K> {
    /// Create a client from a signer and a store.
    pub fn new(key: K, store: S) -> Self {
        Self { key, store }
    }

    /// This device's ID.
    pub fn device_id(&self) -> DeviceId {
        self.key.device_id()
    }

    /// Create a new object with an initial payload.
    pub fn create(&mut self, ty: ObjectType, payload: Vec<u8>) -> Result<Change, ClientError> {
        self.commit(ObjectId::random(), ty, vec![], payload)
    }

    /// Append a change to an existing object, building on its current heads.
    /// Never blocks on a lock: concurrent edits become a fork that the merge
    /// layer resolves (REQ-DATA-004).
    pub fn edit(&mut self, object: ObjectId, payload: Vec<u8>) -> Result<Change, ClientError> {
        let hist = self.store.history(&object)?;
        let ty = hist
            .first()
            .map(|c| c.body.object_type.clone())
            .ok_or(ClientError::UnknownObject(object))?;
        let parents = self.store.heads(&object)?;
        self.commit(object, ty, parents, payload)
    }

    /// Validate and store a change received from a peer.
    /// Returns `true` if it was new.
    pub fn receive(&mut self, change: Change) -> Result<bool, ClientError> {
        change.verify()?;
        // TODO(phase 6, REQ-PERM-002): check author permissions under the
        // policy as of the change's parents before storing.
        Ok(self.store.put(change)?)
    }

    /// Handle a frame from the relay: validate and store peers' changes
    /// (REQ-SYNC-004). A bad change from a peer is reported as
    /// [`Event::Rejected`], not as an error, so a misbehaving device cannot
    /// break the receive loop. Only local storage failures return `Err`.
    pub fn handle_frame(&mut self, frame: kith_protocol::Frame) -> Result<Event, ClientError> {
        use kith_protocol::Frame;
        Ok(match frame {
            Frame::Deliver { org, from, body } => {
                let rejected = |reason: String| Event::Rejected {
                    org: org.clone(),
                    from: from.clone(),
                    reason,
                };
                let change = match kith_store::codec::decode_change(&body) {
                    Ok(c) => c,
                    Err(e) => return Ok(rejected(e.to_string())),
                };
                match self.receive(change.clone()) {
                    Ok(is_new) => Event::Received {
                        org,
                        from,
                        change: Box::new(change),
                        is_new,
                    },
                    Err(ClientError::Rejected(e)) => rejected(e.to_string()),
                    Err(e) => return Err(e),
                }
            }
            Frame::Presence { org, online } => Event::Presence { org, online },
            Frame::Receipt { delivered } => Event::Receipt { delivered },
            Frame::Error { code, message } => Event::RelayError { code, message },
            _ => Event::Ignored,
        })
    }

    /// The merged state of an object: all its changes, including concurrent
    /// forks, combined by `merger` (REQ-DATA-004). Does not change the store;
    /// the next `edit` names all current heads as parents, which joins forks.
    pub fn materialize<M: Merger>(
        &self,
        object: &ObjectId,
        merger: &M,
    ) -> Result<Materialized<M::State>, ClientError> {
        let hist = self.store.history(object)?;
        if hist.is_empty() {
            return Err(ClientError::UnknownObject(*object));
        }
        Ok(merger.materialize(&hist)?)
    }

    /// Full change history of an object.
    pub fn history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        Ok(self.store.history(object)?)
    }

    /// The signer this client was created with (for `DeviceKey`: read the
    /// secret seed to persist it, see `DeviceKey::secret_bytes`).
    pub fn signer(&self) -> &K {
        &self.key
    }

    /// Access the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn commit(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
        parents: Vec<ChangeId>,
        payload: Vec<u8>,
    ) -> Result<Change, ClientError> {
        let change = Change::sign(
            UnsignedChange {
                object_id,
                object_type,
                parents,
                timestamp_ms: now_ms(),
                payload,
            },
            &self.key,
        );
        self.store.put(change.clone())?;
        Ok(change)
    }
}

/// Wall-clock time in milliseconds since the Unix epoch.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock time in milliseconds since the Unix epoch.
/// `std::time::SystemTime::now()` panics on wasm32-unknown-unknown, so use the JS clock.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client<MemoryStore> {
        Client::new(DeviceKey::generate(), MemoryStore::new())
    }

    /// req: REQ-DATA-003
    #[test]
    fn edits_build_history() {
        let mut c = client();
        let created = c.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let oid = created.body.object_id;
        let edited = c.edit(oid, b"v2".to_vec()).unwrap();
        assert_eq!(edited.body.parents, vec![created.change_id]);
        assert_eq!(c.history(&oid).unwrap().len(), 2);
    }

    /// req: REQ-DATA-004
    #[test]
    fn concurrent_edits_fork_without_locks() {
        let mut a = client();
        let mut b = client();
        let created = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let oid = created.body.object_id;
        b.receive(created).unwrap();

        let ea = a.edit(oid, b"a".to_vec()).unwrap();
        let eb = b.edit(oid, b"b".to_vec()).unwrap();
        a.receive(eb).unwrap();
        b.receive(ea).unwrap();

        assert_eq!(a.store().heads(&oid).unwrap().len(), 2);
        assert_eq!(b.store().heads(&oid).unwrap().len(), 2);
    }

    fn deliver(from: &DeviceKey, c: &Change) -> kith_protocol::Frame {
        kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: from.device_id().to_hex(),
            body: kith_store::codec::encode_change(c),
        }
    }

    /// req: REQ-SYNC-004
    #[test]
    fn delivered_change_is_validated_and_stored() {
        let (ka, mut b) = (DeviceKey::generate(), client());
        let mut a = Client::new(ka, MemoryStore::new());
        let c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let frame = broadcast_frame("org", &c);
        let kith_protocol::Frame::Broadcast { body, .. } = frame else {
            panic!("broadcast frame expected")
        };
        let delivered = kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: a.device_id().to_hex(),
            body,
        };
        let ev = b.handle_frame(delivered.clone()).unwrap();
        assert!(matches!(ev, Event::Received { is_new: true, .. }));
        assert!(b.store().contains(&c.change_id).unwrap());
        // Delivered again: valid, but not new.
        assert!(matches!(
            b.handle_frame(delivered).unwrap(),
            Event::Received { is_new: false, .. }
        ));
    }

    /// req: REQ-SYNC-004
    #[test]
    fn bad_delivered_changes_are_rejected_not_fatal() {
        let ka = DeviceKey::generate();
        let mut b = client();
        let mut a = Client::new(ka, MemoryStore::new());
        let mut c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        c.body.payload = b"tampered".to_vec();
        let from = DeviceKey::generate();
        assert!(matches!(
            b.handle_frame(deliver(&from, &c)).unwrap(),
            Event::Rejected { .. }
        ));
        assert!(!b.store().contains(&c.change_id).unwrap());
        let garbage = kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: "x".into(),
            body: vec![1, 2, 3],
        };
        assert!(matches!(
            b.handle_frame(garbage).unwrap(),
            Event::Rejected { .. }
        ));
    }

    /// req: REQ-PERM-002
    #[test]
    fn invalid_change_is_not_stored() {
        let mut a = client();
        let mut b = client();
        let mut c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        c.body.payload = b"tampered".to_vec();
        assert!(b.receive(c.clone()).is_err());
        assert!(!b.store().contains(&c.change_id).unwrap());
    }
}
