//! JavaScript/TypeScript bindings via wasm-bindgen.
//! Build: `wasm-pack build bindings/wasm --target web --scope <npm-scope>`.

#![allow(missing_docs)] // wasm-bindgen generates items

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    kith_client::kith_core_version().to_string()
}

/// Client handle for JavaScript.
#[wasm_bindgen]
pub struct KithClient {
    inner: Client<MemoryStore>,
}

#[wasm_bindgen]
impl KithClient {
    /// New client with a fresh device key and in-memory store.
    ///
    /// The identity is lost on reload unless the app saves `secretKey()` and
    /// restores it with `KithClient.withSecretKey`.
    /// TODO(phase 1): IndexedDB-backed store.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Client::new(DeviceKey::generate(), MemoryStore::new()),
        }
    }

    /// Restore a device identity from its 32-byte secret key (as returned by
    /// `secretKey()`), with an in-memory store.
    #[wasm_bindgen(js_name = withSecretKey)]
    pub fn with_secret_key(secret_key: &[u8]) -> Result<KithClient, JsError> {
        let seed: [u8; 32] = secret_key.try_into().map_err(|_| {
            JsError::new(&format!(
                "secret key must be 32 bytes, got {}",
                secret_key.len()
            ))
        })?;
        Ok(Self {
            inner: Client::new(DeviceKey::from_secret_bytes(&seed), MemoryStore::new()),
        })
    }

    /// The 32-byte secret key of this device. Anyone who has it can sign as
    /// this device: keep it out of logs and plain `localStorage`; prefer a
    /// non-extractable `CryptoKey`-wrapped blob or app-level encryption.
    #[wasm_bindgen(js_name = secretKey)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.inner.signer().secret_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.inner.device_id().to_hex()
    }

    /// Create an object; returns its object ID (hex).
    pub fn create(&mut self, object_type: &str, payload: &[u8]) -> Result<String, JsError> {
        let c = self
            .inner
            .create(ObjectType::new(object_type), payload.to_vec())
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(c.body.object_id.to_hex())
    }

    /// Append a change; returns the change ID (hex).
    pub fn edit(&mut self, object_id: &str, payload: &[u8]) -> Result<String, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(|e| JsError::new(&e.to_string()))?;
        let c = self
            .inner
            .edit(oid, payload.to_vec())
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(c.change_id.to_hex())
    }

    /// Number of changes in an object's history.
    #[wasm_bindgen(js_name = historyLength)]
    pub fn history_length(&self, object_id: &str) -> Result<usize, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(self
            .inner
            .history(&oid)
            .map_err(|e| JsError::new(&e.to_string()))?
            .len())
    }
}

impl Default for KithClient {
    fn default() -> Self {
        Self::new()
    }
}
