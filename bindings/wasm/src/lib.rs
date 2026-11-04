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

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn wrap(key: DeviceKey, store: Box<dyn Store>) -> Result<KithClient, JsError> {
    Ok(KithClient {
        inner: Rc::new(RefCell::new(Client::new(key, store).map_err(js_err)?)),
        live: None,
    })
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
            .expect("an empty memory store has no MLS state to load")
    }

    /// Restore a device identity from its 32-byte secret key (as returned by
    /// `secretKey()`), with an in-memory store.
    #[wasm_bindgen(js_name = withSecretKey)]
    pub fn with_secret_key(secret_key: &[u8]) -> Result<KithClient, JsError> {
        wrap(device_key(secret_key)?, Box::new(MemoryStore::new()))
    }

    /// Persistent client: changes and the MLS group state are stored in the
    /// IndexedDB database `dbName` (created if missing) and the identity comes from
    /// `secretKey`. Returns a Promise. Opening the same `dbName` with the same key
    /// later restores all data, the identity and group membership. The database
    /// holds group secrets.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(db_name: String, secret_key: Vec<u8>) -> Result<KithClient, JsError> {
        let key = device_key(&secret_key)?;
        let store = idb::IdbStore::open(&db_name)
            .await
            .map_err(|e| JsError::new(&idb::js_message(&e)))?;
        wrap(key, Box::new(store))
    }

    /// Connect to a relay (`ws://host:port/v1/ws`, `wss://` in production),
    /// authenticate as this device and join `org`. From then on every
    /// `create`/`edit` is broadcast to the other online devices, and their
    /// changes are validated and stored. `onEvent` receives plain objects:
    /// `{type: "received", org, from, objectId, changeId, isNew}`,
    /// `{type: "rejected", org, from, reason}`, `{type: "presence", org, online}`,
    /// `{type: "receipt", delivered}`, `{type: "relayError", code, message}`,
    /// `{type: "syncServed", ...}`, `{type: "syncReceived", ...}`, group events
    /// (`joinRequested` with `keyPackage`, `joined`, `groupChanged`, `epochBehind`,
    /// `commitsServed`, `commitsApplied`, `reAddRequested`, `memberReAdded`),
    /// `{type: "closed"}` and `{type: "error"}`.
    ///
    /// Every body is encrypted for `org`'s MLS group: the device must be a member
    /// (`createGroup` on the first device; `requestJoin` + `addMember` for others).
    /// Only devices online at the same time are reached; use `catchUp` for the rest.
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

    /// Ask one online peer for the changes this device lacks and offer it ours
    /// (catch-up). Use it after connecting, once a `presence` event shows another
    /// device, and on a new device to download the full history. The peer's
    /// answer arrives as `syncReceived` / `syncServed` events; a `receipt` with an
    /// empty `delivered` list means nobody was online.
    #[wasm_bindgen(js_name = catchUp)]
    pub fn catch_up(&self) -> Result<(), JsError> {
        match &self.live {
            Some(live) => live.catch_up(&self.inner).map_err(|e| JsError::new(&e)),
            None => Err(JsError::new("not connected: call connect first")),
        }
    }

    /// Create `org`'s encrypted group with this device as its only member. Call it
    /// once, on the device that creates the organization.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&self, org: &str) -> Result<(), JsError> {
        self.inner.borrow_mut().create_group(org).map_err(js_err)
    }

    /// True if this device is a member of `org`'s group.
    #[wasm_bindgen(js_name = isMember)]
    pub fn is_member(&self, org: &str) -> bool {
        self.inner.borrow().is_member(org)
    }

    /// Devices (hex IDs) in `org`'s group.
    #[wasm_bindgen(js_name = groupMembers)]
    pub fn group_members(&self, org: &str) -> Result<Vec<String>, JsError> {
        self.inner.borrow().group_members(org).map_err(js_err)
    }

    /// Ask the member `to` (hex device ID, e.g. from a `presence` event) to add this
    /// device to the connected org. A `joined` event follows if it admits us.
    #[wasm_bindgen(js_name = requestJoin)]
    pub fn request_join(&self, to: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let f = self
            .inner
            .borrow_mut()
            .join_request_frame(live.org(), to)
            .map_err(js_err)?;
        live.send(&[f]);
        Ok(())
    }

    /// Admit the device of a `joinRequested` event (pass its `keyPackage`).
    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&self, key_package: &[u8]) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .add_member(live.org(), key_package)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Remove `device` (hex) from the connected org's group.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&self, device: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let f = self
            .inner
            .borrow_mut()
            .remove_member(live.org(), device)
            .map_err(js_err)?;
        live.send(&[f]);
        Ok(())
    }

    /// Rotate this device's key in the connected org's group (do it periodically).
    #[wasm_bindgen(js_name = rotateKey)]
    pub fn rotate_key(&self) -> Result<(), JsError> {
        let live = self.live()?;
        let f = self
            .inner
            .borrow_mut()
            .rotate_key(live.org())
            .map_err(js_err)?;
        live.send(&[f]);
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
    fn live(&self) -> Result<&live::Live, JsError> {
        self.live
            .as_ref()
            .ok_or_else(|| JsError::new("not connected: call connect first"))
    }

    /// Broadcast if connected. A change made before this device is in the group
    /// stays local and reaches peers through catch-up later.
    fn broadcast(&self, change: &kith_client::Change) {
        if let Some(live) = &self.live
            && let Err(e) = live.broadcast(&self.inner, change)
        {
            web_sys::console::warn_1(&format!("kith: change not broadcast: {e}").into());
        }
    }
}

impl Default for KithClient {
    fn default() -> Self {
        Self::new()
    }
}
