//! JavaScript/TypeScript bindings via wasm-bindgen.
//! Build: `wasm-pack build bindings/wasm --target web --scope <npm-scope>`.

#![allow(missing_docs)] // wasm-bindgen generates items

use std::{cell::RefCell, rc::Rc};

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use wasm_bindgen::prelude::*;

mod idb;
mod live;
mod lock;

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
    /// Keeps other tabs off the same IndexedDB database (see `lock.rs`).
    _lock: Option<lock::TabLock>,
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn parse_role(s: &str) -> Result<kith_client::Role, JsError> {
    kith_client::Role::parse(s)
        .ok_or_else(|| JsError::new(&format!("unknown role {s:?}: use viewer, editor or admin")))
}

fn wrap(
    key: DeviceKey,
    store: Box<dyn Store>,
    lock: Option<lock::TabLock>,
) -> Result<KithClient, JsError> {
    Ok(KithClient {
        inner: Rc::new(RefCell::new(Client::new(key, store).map_err(js_err)?)),
        live: None,
        _lock: lock,
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
        wrap(DeviceKey::generate(), Box::new(MemoryStore::new()), None)
            .expect("an empty memory store has no MLS state to load")
    }

    /// Restore a device identity from its 32-byte secret key (as returned by
    /// `secretKey()`), with an in-memory store.
    #[wasm_bindgen(js_name = withSecretKey)]
    pub fn with_secret_key(secret_key: &[u8]) -> Result<KithClient, JsError> {
        wrap(device_key(secret_key)?, Box::new(MemoryStore::new()), None)
    }

    /// Persistent client: changes and the MLS group state are stored in the
    /// IndexedDB database `dbName` (created if missing) and the identity comes from
    /// `secretKey`. Returns a Promise. Opening the same `dbName` with the same key
    /// later restores all data, the identity and group membership. The database
    /// holds group secrets.
    ///
    /// Only one client may own a database at a time: it takes an exclusive Web Lock
    /// (`navigator.locks`) held until the client is freed or the page closes. If
    /// another tab holds it, this rejects, or with `waitForLock = true` waits until that
    /// tab is gone (leader election: the waiting tab takes over).
    #[wasm_bindgen(js_name = open)]
    pub async fn open(
        db_name: String,
        secret_key: Vec<u8>,
        wait_for_lock: Option<bool>,
    ) -> Result<KithClient, JsError> {
        let key = device_key(&secret_key)?;
        let lock = lock::acquire(&db_name, wait_for_lock.unwrap_or(false)).await?;
        let store = idb::IdbStore::open(&db_name)
            .await
            .map_err(|e| JsError::new(&idb::js_message(&e)))?;
        wrap(key, Box::new(store), lock)
    }

    /// Restore a device from a backup (`exportBackup`) into the IndexedDB database
    /// `dbName` (use a new one). Returns a Promise. Same identity and data; it rejoins
    /// its groups (fresh keys) once a member is online. Only when the original
    /// device is gone.
    #[wasm_bindgen(js_name = restoreBackup)]
    pub async fn restore_backup(
        db_name: String,
        backup: Vec<u8>,
        passphrase: String,
        wait_for_lock: Option<bool>,
    ) -> Result<KithClient, JsError> {
        let lock = lock::acquire(&db_name, wait_for_lock.unwrap_or(false)).await?;
        let store = idb::IdbStore::open(&db_name)
            .await
            .map_err(|e| JsError::new(&idb::js_message(&e)))?;
        let c = Client::import_backup(&backup, &passphrase, Box::new(store) as Box<dyn Store>)
            .map_err(js_err)?;
        Ok(KithClient {
            inner: Rc::new(RefCell::new(c)),
            live: None,
            _lock: lock,
        })
    }

    /// A passphrase-encrypted backup of this device (identity, data, files,
    /// memberships) as bytes. Anyone with it and the passphrase can act as this device.
    #[wasm_bindgen(js_name = exportBackup)]
    pub fn export_backup(&self, passphrase: &str) -> Result<Vec<u8>, JsError> {
        self.inner
            .borrow()
            .export_backup(passphrase)
            .map_err(js_err)
    }

    /// Connect to a relay (`ws://host:port/v1/ws`, `wss://` in production),
    /// authenticate as this device and join `org`. From then on every
    /// `create`/`edit` is broadcast to the other online devices, and their
    /// changes are validated and stored. `onEvent` receives plain objects:
    /// `{type: "received", org, from, objectId, changeId, isNew}`,
    /// `{type: "rejected", org, from, reason}`, `{type: "presence", org, online}`,
    /// `{type: "receipt", delivered}`, `{type: "relayError", code, message}`,
    /// `{type: "syncServed", from}`, `{type: "syncCompared", from, sending, wanting}`,
    /// `{type: "syncReceived", ...}`, group events
    /// (`inviteClaimed` with `from` and `code`, `claimCode` with `org`, `from` and
    /// `code`, `joined`, `certificateUpdated`,
    /// `groupChanged`, `epochBehind`, `commitsServed`, `commitsApplied`,
    /// `reAddRequested`, `memberReAdded`, `fork`) and the connection's own events:
    /// `{type: "connected"}` (handshake started), `{type: "closed"}`,
    /// `{type: "reconnecting", attempt, delayMs}` and `{type: "error"}`.
    ///
    /// The connection reconnects by itself (1 s, doubling to 30 s, at once when the
    /// browser comes back online) until `disconnect`. Changes made while offline are
    /// stored; after `connected` and a `presence` event call `catchUp` to exchange them.
    ///
    /// Every body is encrypted for `org`'s MLS group: the device must be a member
    /// (`createOrg` on the first device; others join with an invite: `createInvite`,
    /// then `claimInvite` on the new device and `acceptClaim` on the admin). A device
    /// that is not a member yet connects as *pending* and can only claim.
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
    /// device, and on a new device to download the full history. The result arrives
    /// as a `syncCompared` event (`sending` and `wanting` both 0: in sync), then
    /// `syncReceived`; a `receipt` with an empty `delivered` list means nobody was online.
    #[wasm_bindgen(js_name = catchUp)]
    pub fn catch_up(&self) -> Result<(), JsError> {
        match &self.live {
            Some(live) => live.catch_up(&self.inner).map_err(|e| JsError::new(&e)),
            None => Err(JsError::new("not connected: call connect first")),
        }
    }

    /// Create an organization; returns its ID (the org root public key, hex). This
    /// device becomes its first admin and keeps the root key.
    #[wasm_bindgen(js_name = createOrg)]
    pub fn create_org(&self) -> Result<String, JsError> {
        self.inner.borrow_mut().create_org().map_err(js_err)
    }

    /// True if this device may invite and admit devices to `org`.
    #[wasm_bindgen(js_name = isAdmin)]
    pub fn is_admin(&self, org: &str) -> bool {
        self.inner.borrow().is_admin(org)
    }

    /// A one-time invite link to `org`, valid for `ttlSeconds`, pointing the new
    /// device at `relay`. Admins only; stay online until the `inviteClaimed` event.
    #[wasm_bindgen(js_name = createInvite)]
    pub fn create_invite(
        &self,
        org: &str,
        relay: &str,
        ttl_seconds: f64,
    ) -> Result<String, JsError> {
        self.inner
            .borrow_mut()
            .create_invite(org, relay, (ttl_seconds.max(0.0) * 1000.0) as u64)
            .map_err(js_err)
    }

    /// A one-time link to add another device of *this user* to `org` (REQ-ID-002).
    /// Any member can make one, not only admins; the new device gets this device's
    /// role (at most editor). Stay online until the `inviteClaimed` event, then
    /// `acceptClaim`. Not available on a device that was itself added this way.
    #[wasm_bindgen(js_name = createOwnDeviceInvite)]
    pub fn create_own_device_invite(
        &self,
        org: &str,
        relay: &str,
        ttl_seconds: f64,
    ) -> Result<String, JsError> {
        self.inner
            .borrow_mut()
            .create_own_device_invite(org, relay, (ttl_seconds.max(0.0) * 1000.0) as u64)
            .map_err(js_err)
    }

    /// Read an invite link without claiming it: `{org, relay, expiresMs}`, so the app
    /// knows where to `connect` before `claimInvite`.
    #[wasm_bindgen(js_name = parseInvite)]
    pub fn parse_invite(link: &str) -> Result<js_sys::Object, JsError> {
        let inv = kith_client::Invite::parse(link).map_err(js_err)?;
        let o = js_sys::Object::new();
        let set = |k: &str, v: JsValue| js_sys::Reflect::set(&o, &k.into(), &v).map(|_| ());
        set("org", inv.org.to_hex().into()).map_err(|_| JsError::new("object"))?;
        set("relay", inv.relay.into()).map_err(|_| JsError::new("object"))?;
        set("expiresMs", (inv.expires_ms as f64).into()).map_err(|_| JsError::new("object"))?;
        Ok(o)
    }

    /// Claim an invite link on the new device (connect to its relay and org first).
    /// The admin answers with a `claimCode` event (`code`: the short code to show);
    /// a `joined` event follows once it accepts.
    #[wasm_bindgen(js_name = claimInvite)]
    pub fn claim_invite(&self, link: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let claim = self.inner.borrow_mut().claim_invite(link).map_err(js_err)?;
        if claim.org != live.org() {
            return Err(JsError::new(
                "the invite is for another org than the connection",
            ));
        }
        live.send(&[claim.frame]);
        Ok(())
    }

    /// Admit the device of an `inviteClaimed` event (its `from`), after comparing
    /// `code` with the new device's screen if the app wants to.
    #[wasm_bindgen(js_name = acceptClaim)]
    pub fn accept_claim(&self, device: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .accept_claim(live.org(), device)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Refuse the claim of an `inviteClaimed` event; the invite stays valid.
    #[wasm_bindgen(js_name = rejectClaim)]
    pub fn reject_claim(&self, device: &str) -> Result<(), JsError> {
        let live = self.live()?;
        self.inner.borrow_mut().reject_claim(live.org(), device);
        Ok(())
    }

    /// Make a member an admin of the connected org (only the org's creator can).
    #[wasm_bindgen(js_name = grantAdmin)]
    pub fn grant_admin(&self, device: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .grant_admin(live.org(), device)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Set a member's role in the connected org: `"viewer"`, `"editor"` or
    /// `"admin"` (admin only from the org's creator). Admins only.
    #[wasm_bindgen(js_name = setRole)]
    pub fn set_role(&self, device: &str, role: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let role = parse_role(role)?;
        let mut c = self.inner.borrow_mut();
        let change = c.set_role(live.org(), device, role).map_err(js_err)?;
        let f = c.broadcast_frame(live.org(), &change).map_err(js_err)?;
        live.send(&[f]);
        Ok(())
    }

    /// Set the minimum role that may write objects of `objectType` in the connected
    /// org (`"viewer"`, `"editor"`, `"admin"`). Admins only.
    #[wasm_bindgen(js_name = setWriteRule)]
    pub fn set_write_rule(&self, object_type: &str, role: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let role = parse_role(role)?;
        let mut c = self.inner.borrow_mut();
        let change = c
            .set_write_rule(live.org(), object_type, role)
            .map_err(js_err)?;
        let f = c.broadcast_frame(live.org(), &change).map_err(js_err)?;
        live.send(&[f]);
        Ok(())
    }

    /// A device's role in `org`: `"viewer"`, `"editor"`, `"admin"`, or `undefined`
    /// if revoked.
    #[wasm_bindgen(js_name = roleOf)]
    pub fn role_of(&self, org: &str, device: &str) -> Result<Option<String>, JsError> {
        Ok(self
            .inner
            .borrow()
            .role_of(org, device)
            .map_err(js_err)?
            .map(|r| r.as_str().to_string()))
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

    /// Create read-restricted subgroup `name` of the connected org with `members`
    /// (array of hex IDs; admins only). Data created with
    /// `createIn(org + "/" + name, ...)` only reaches its members. This device runs
    /// the subgroup and must be online for members to be added.
    #[wasm_bindgen(js_name = createSubgroup)]
    pub fn create_subgroup(&self, name: &str, members: Vec<String>) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .create_subgroup(live.org(), name, &members)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Replace the members of subgroup `name` of the connected org (admins only).
    #[wasm_bindgen(js_name = setSubgroupMembers)]
    pub fn set_subgroup_members(&self, name: &str, members: Vec<String>) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .set_subgroup_members(live.org(), name, &members)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Members of subgroup `name` of `org` per the policy, or `undefined`.
    #[wasm_bindgen(js_name = subgroupMembers)]
    pub fn subgroup_members(&self, org: &str, name: &str) -> Option<Vec<String>> {
        self.inner.borrow().subgroup_members(org, name)
    }

    /// Subgroups of `org` this device can read.
    #[wasm_bindgen(js_name = mySubgroups)]
    pub fn my_subgroups(&self, org: &str) -> Vec<String> {
        self.inner.borrow().my_subgroups(org)
    }

    /// Remove `device` (hex) from the connected org: out of the encrypted group and
    /// revoked in the policy. Admins only.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&self, device: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let frames = self
            .inner
            .borrow_mut()
            .remove_member(live.org(), device)
            .map_err(js_err)?;
        live.send(&frames);
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

    /// Create an object in `scope` (an org ID this device is a member of, or
    /// `"local"`); returns its object ID. `create` uses the only org, or `local`
    /// before joining one.
    #[wasm_bindgen(js_name = createIn)]
    pub fn create_in(
        &mut self,
        scope: &str,
        object_type: &str,
        payload: &[u8],
    ) -> Result<String, JsError> {
        let scope = kith_client::Scope::parse(scope).map_err(js_err)?;
        let c = self
            .inner
            .borrow_mut()
            .create_in(scope, ObjectType::new(object_type), payload.to_vec())
            .map_err(js_err)?;
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

    /// Create a JSON document (an object whose edits merge without conflicts, see
    /// `updateDocument`) from a JSON object string; returns its object ID (hex).
    /// Broadcast to the other online devices when connected.
    #[wasm_bindgen(js_name = createDocument)]
    pub fn create_document(&mut self, object_type: &str, json: &str) -> Result<String, JsError> {
        let c = self
            .inner
            .borrow_mut()
            .create_document(ObjectType::new(object_type), json)
            .map_err(js_err)?;
        self.broadcast(&c);
        Ok(c.body.object_id.to_hex())
    }

    /// Change a document with a JSON merge patch (RFC 7396: `null` removes a key,
    /// objects merge, other values replace); returns the change ID, or `undefined`
    /// if the patch changes nothing. Edits of different keys on different devices
    /// all survive.
    #[wasm_bindgen(js_name = updateDocument)]
    pub fn update_document(
        &mut self,
        object_id: &str,
        patch: &str,
    ) -> Result<Option<String>, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(js_err)?;
        let c = self
            .inner
            .borrow_mut()
            .update_document(oid, patch)
            .map_err(js_err)?;
        Ok(c.map(|c| {
            self.broadcast(&c);
            c.change_id.to_hex()
        }))
    }

    /// The merged state of a document as a JSON string (`JSON.parse` it). Call it
    /// again on `received` / `syncReceived` events to re-render.
    #[wasm_bindgen(js_name = documentJson)]
    pub fn document_json(&self, object_id: &str) -> Result<String, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(js_err)?;
        self.inner.borrow().document_json(&oid).map_err(js_err)
    }

    /// Store a file (encrypted, in chunks) in the default scope; returns its object
    /// ID. Broadcast to the other online devices when connected; they fetch the
    /// chunks with `fetchFile`.
    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(&mut self, name: &str, mime: &str, data: &[u8]) -> Result<String, JsError> {
        let c = self
            .inner
            .borrow_mut()
            .add_file(name, mime, data)
            .map_err(js_err)?;
        self.broadcast(&c);
        Ok(c.body.object_id.to_hex())
    }

    /// `addFile` in `scope` (an org ID, `org/subgroup`, or `"local"`).
    #[wasm_bindgen(js_name = addFileIn)]
    pub fn add_file_in(
        &mut self,
        scope: &str,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<String, JsError> {
        let scope = kith_client::Scope::parse(scope).map_err(js_err)?;
        let c = self
            .inner
            .borrow_mut()
            .add_file_in(scope, name, mime, data)
            .map_err(js_err)?;
        self.broadcast(&c);
        Ok(c.body.object_id.to_hex())
    }

    /// `{name, mime, size, chunks, missing}` of a file object.
    #[wasm_bindgen(js_name = fileInfo)]
    pub fn file_info(&self, object_id: &str) -> Result<js_sys::Object, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(js_err)?;
        let i = self.inner.borrow().file_info(&oid).map_err(js_err)?;
        let o = js_sys::Object::new();
        for (k, v) in [
            ("name", JsValue::from_str(&i.name)),
            ("mime", JsValue::from_str(&i.mime)),
            ("size", JsValue::from_f64(i.size as f64)),
            ("chunks", JsValue::from_f64(i.chunks as f64)),
            ("missing", JsValue::from_f64(i.missing as f64)),
        ] {
            js_sys::Reflect::set(&o, &k.into(), &v).map_err(|_| JsError::new("object"))?;
        }
        Ok(o)
    }

    /// The contents of a file whose chunks are all here (`fetchFile` first).
    #[wasm_bindgen(js_name = readFile)]
    pub fn read_file(&self, object_id: &str) -> Result<Vec<u8>, JsError> {
        let oid = ObjectId::from_hex(object_id).map_err(js_err)?;
        self.inner.borrow().read_file(&oid).map_err(js_err)
    }

    /// Fetch a file's missing chunks from a peer; `fileChunks` events report
    /// progress (`ready` lists complete files), `chunksMissing` if the peer lacks some.
    #[wasm_bindgen(js_name = fetchFile)]
    pub fn fetch_file(&self, object_id: &str) -> Result<(), JsError> {
        let live = self.live()?;
        let oid = ObjectId::from_hex(object_id).map_err(js_err)?;
        let frames = self
            .inner
            .borrow_mut()
            .fetch_file_frames(live.org(), &oid)
            .map_err(js_err)?;
        live.send(&frames);
        Ok(())
    }

    /// Fetch every new file's chunks as soon as it arrives (default: only on `fetchFile`).
    #[wasm_bindgen(js_name = setFetchFiles)]
    pub fn set_fetch_files(&self, eager: bool) {
        self.inner.borrow_mut().set_fetch_files(eager);
    }

    /// The objects this device knows, oldest first, optionally only of one type:
    /// an array of `{objectId, objectType, scope, author, createdMs}`. Includes
    /// documents and file objects. Walks the whole store: call it to build a list,
    /// then update the list from `received` / `syncReceived` events.
    pub fn objects(&self, object_type: Option<String>) -> Result<js_sys::Array, JsError> {
        let list = self
            .inner
            .borrow()
            .objects(object_type.as_deref())
            .map_err(js_err)?;
        let out = js_sys::Array::new();
        for c in list {
            let o = js_sys::Object::new();
            let put = |k: &str, v: JsValue| {
                let _ = js_sys::Reflect::set(&o, &k.into(), &v);
            };
            put("objectId", c.body.object_id.to_hex().into());
            put("objectType", c.body.object_type.as_str().into());
            put("scope", c.body.scope.as_str().into());
            put("author", c.author.to_hex().into());
            put("createdMs", (c.body.timestamp_ms as f64).into());
            out.push(&o);
        }
        Ok(out)
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
