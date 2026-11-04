//! Foreign-language bindings (UniFFI) for Swift and Kotlin.
//!
//! Keep this layer thin: convert types and errors, call into `kith-client`.
//! Anything with logic belongs in the Rust crates so every platform behaves
//! identically.

#![allow(missing_docs)] // UniFFI generates items

use std::sync::Mutex;

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType};

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
into_kith_error!(kith_client::ClientError, kith_client::IdError);

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
    inner: Mutex<Client<MemoryStore>>,
}

#[uniffi::export]
impl KithClient {
    /// New client with a fresh device key and in-memory store.
    ///
    /// The identity is lost when the client is dropped unless the app saves
    /// `secret_key()` and restores it with `with_secret_key`.
    /// TODO(phase 1): database path / store selection.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Client::new(DeviceKey::generate(), MemoryStore::new())),
        }
    }

    /// New client that restores a device identity from its 32-byte secret key
    /// (as returned by `secret_key()`), with an in-memory store.
    #[uniffi::constructor]
    pub fn with_secret_key(secret_key: Vec<u8>) -> Result<Self, KithError> {
        let seed: [u8; 32] = secret_key
            .try_into()
            .map_err(|v: Vec<u8>| KithError::Failed {
                msg: format!("secret key must be 32 bytes, got {}", v.len()),
            })?;
        Ok(Self {
            inner: Mutex::new(Client::new(
                DeviceKey::from_secret_bytes(&seed),
                MemoryStore::new(),
            )),
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
    #[test]
    fn rejects_wrong_length_secret_key() {
        assert!(KithClient::with_secret_key(vec![0; 31]).is_err());
        assert!(KithClient::with_secret_key(vec![0; 33]).is_err());
    }
}
