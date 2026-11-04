//! JavaScript/TypeScript bindings via wasm-bindgen.
//! Build: `wasm-pack build bindings/wasm --target web --scope <npm-scope>`.

#![allow(missing_docs)] // wasm-bindgen generates items

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use wasm_bindgen::prelude::*;

mod idb;

fn device_key(secret_key: &[u8]) -> Result<DeviceKey, JsError> {
    let seed: [u8; 32] = secret_key.try_into().map_err(|_| {
        JsError::new(&format!(
            "secret key must be 32 bytes, got {}",
            secret_key.len()
        ))
    })?;
    Ok(DeviceKey::from_secret_bytes(&seed))
}

/// A new random 32-byte device secret key. Save it before first use, then pass it to `KithClient.open`.
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Vec<u8> {
    DeviceKey::generate().secret_bytes().to_vec()
}

#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    kith_client::kith_core_version().to_string()
}

/// Client handle for JavaScript.
#[wasm_bindgen]
pub struct KithClient {
    inner: Client<Box<dyn Store>>,
}

#[wasm_bindgen]
impl KithClient {
    /// New client with a fresh device key and in-memory store.
    ///
    /// The identity is lost on reload unless the app saves `secretKey()` and
    /// restores it with `KithClient.withSecretKey`.
    /// For persistence use `KithClient.open`.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Client::new(DeviceKey::generate(), Box::new(MemoryStore::new())),
        }
    }

    /// Restore a device identity from its 32-byte secret key (as returned by
    /// `secretKey()`), with an in-memory store.
    #[wasm_bindgen(js_name = withSecretKey)]
    pub fn with_secret_key(secret_key: &[u8]) -> Result<KithClient, JsError> {
        Ok(Self {
            inner: Client::new(device_key(secret_key)?, Box::new(MemoryStore::new())),
        })
    }

    /// Persistent client: changes are stored in the IndexedDB database
    /// `dbName` (created if missing) and the identity comes from `secretKey`.
    /// Returns a Promise. Opening the same `dbName` with the same key later
    /// restores all data and the identity.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(db_name: String, secret_key: Vec<u8>) -> Result<KithClient, JsError> {
        let key = device_key(&secret_key)?;
        let store = idb::IdbStore::open(&db_name)
            .await
            .map_err(|e| JsError::new(&idb::js_message(&e)))?;
        Ok(Self {
            inner: Client::new(key, Box::new(store)),
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
