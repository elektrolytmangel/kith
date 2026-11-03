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

    /// Full change history of an object.
    pub fn history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        Ok(self.store.history(object)?)
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
