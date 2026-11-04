//! JavaScript/TypeScript bindings via wasm-bindgen.
//! Build: `wasm-pack build bindings/wasm --target web --scope <npm-scope>`.

#![allow(missing_docs)] // wasm-bindgen generates items

use std::{cell::RefCell, rc::Rc};

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use wasm_bindgen::prelude::*;

mod idb;
mod live;

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
    inner: live::SharedClient,
    live: Option<live::Live>,
}

fn wrap(key: DeviceKey, store: Box<dyn Store>) -> KithClient {
    KithClient {
        inner: Rc::new(RefCell::new(Client::new(key, store))),
        live: None,
    }
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
        wrap(DeviceKey::generate(), Box::new(MemoryStore::new()))
    }

    /// Restore a device identity from its 32-byte secret key (as returned by
    /// `secretKey()`), with an in-memory store.
    #[wasm_bindgen(js_name = withSecretKey)]
    pub fn with_secret_key(secret_key: &[u8]) -> Result<KithClient, JsError> {
        Ok(wrap(device_key(secret_key)?, Box::new(MemoryStore::new())))
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
        Ok(wrap(key, Box::new(store)))
    }

    /// Connect to a relay (`ws://host:port/v1/ws`, `wss://` in production),
    /// authenticate as this device and join `org`. From then on every
    /// `create`/`edit` is broadcast to the other online devices, and their
    /// changes are validated and stored. `onEvent` receives plain objects:
    /// `{type: "received", org, from, objectId, changeId, isNew}`,
    /// `{type: "rejected", org, from, reason}`, `{type: "presence", org, online}`,
    /// `{type: "receipt", delivered}`, `{type: "relayError", code, message}`,
    /// `{type: "closed"}` and `{type: "error"}`.
    ///
    /// Only devices online at the same time are reached; changes made while
    /// offline are not sent later (catch-up sync is not implemented yet), and
    /// message bodies are not encrypted yet.
    pub fn connect(
        &mut self,
        url: &str,
        org: &str,
        on_event: js_sys::Function,
    ) -> Result<(), JsError> {
        self.disconnect();
        let live = live::Live::connect(self.inner.clone(), url, org, on_event)
            .map_err(|e| JsError::new(&idb::js_message(&e)))?;
        self.live = Some(live);
        Ok(())
    }

    /// Close the relay connection, if any.
    pub fn disconnect(&mut self) {
        if let Some(live) = self.live.take() {
            live.close();
        }
    }

    /// The 32-byte secret key of this device. Anyone who has it can sign as
    /// this device: keep it out of logs and plain `localStorage`; prefer a
    /// non-extractable `CryptoKey`-wrapped blob or app-level encryption.
    #[wasm_bindgen(js_name = secretKey)]
    pub fn secret_key(&self) -> Vec<u8> {
        self.inner.borrow().signer().secret_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> String {
        self.inner.borrow().device_id().to_hex()
    }

    /// Create an object; returns its object ID (hex).
    pub fn create(&mut self, object_type: &str, payload: &[u8]) -> Result<String, JsError> {
        let c = self
            .inner
            .borrow_mut()
            .create(ObjectType::new(object_type), payload.to_vec())
            .map_err(|e| JsError::new(&e.to_string()))?;
        self.broadcast(&c);
        Ok(c.body.object_id.to_hex())
    }

    /// Append a change; returns the change ID (hex).
    pub fn edit(&mut self, object_id: &str, payload: &[u8]) -> Result<String, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(|e| JsError::new(&e.to_string()))?;
        let c = self
            .inner
            .borrow_mut()
            .edit(oid, payload.to_vec())
            .map_err(|e| JsError::new(&e.to_string()))?;
        self.broadcast(&c);
        Ok(c.change_id.to_hex())
    }

    /// Number of changes in an object's history.
    #[wasm_bindgen(js_name = historyLength)]
    pub fn history_length(&self, object_id: &str) -> Result<usize, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(self
            .inner
            .borrow()
            .history(&oid)
            .map_err(|e| JsError::new(&e.to_string()))?
            .len())
    }
}

impl KithClient {
    fn broadcast(&self, change: &kith_client::Change) {
        if let Some(live) = &self.live {
            live.broadcast(change);
        }
    }
}

impl Default for KithClient {
    fn default() -> Self {
        Self::new()
    }
}
