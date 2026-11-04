//! IndexedDB-backed [`Store`] for browsers, workers and Node (with a
//! compatible `indexedDB`, e.g. `fake-indexeddb` in tests).
//!
//! `Store` is synchronous but IndexedDB is not, so the store keeps every
//! change in memory (loaded once by [`IdbStore::open`]) and writes each new
//! change through to IndexedDB. The write is queued with the browser
//! synchronously inside `put`; only its completion is asynchronous. If it
//! later fails (quota, user clearing data) the error is logged to the console.
//! Changes are append-only rows with auto-increment keys, so the load order
//! is the arrival order. Named blobs (`Store::put_meta`, the MLS state) live in a
//! second object store, `meta`, and are written through the same way.

use js_sys::{Promise, Reflect, Uint8Array};
use kith_client::{Change, ChangeId, MemoryStore, ObjectId, Scope, Store, StoreError};
use kith_store::codec;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Event, IdbDatabase, IdbFactory, IdbObjectStoreParameters, IdbOpenDbRequest, IdbRequest,
    IdbTransactionMode,
};

const STORE: &str = "changes";
const META: &str = "meta";
const CHUNKS: &str = "chunks";
/// 2: `meta` object store. 3: `chunks` (file chunks; key = hex chunk ID, value =
/// scope + data).
const DB_VERSION: u32 = 3;

pub struct IdbStore {
    mem: MemoryStore,
    db: IdbDatabase,
    /// Shared handler for failed background writes.
    on_write_error: Closure<dyn FnMut(Event)>,
}

/// Human-readable message of a JS error value.
pub fn js_message(e: &JsValue) -> String {
    if let Some(s) = e.as_string() {
        return s;
    }
    Reflect::get(e, &"message".into())
        .ok()
        .and_then(|m| m.as_string())
        .unwrap_or_else(|| format!("{e:?}"))
}

/// Resolve with `request.result` on success, reject with its error on failure.
fn request_future(req: &IdbRequest) -> JsFuture {
    JsFuture::from(Promise::new(&mut |resolve, reject| {
        let ok_req = req.clone();
        let ok = Closure::once_into_js(move |_: Event| {
            let _ = resolve.call1(&JsValue::NULL, &ok_req.result().unwrap_or(JsValue::NULL));
        });
        let err_req = req.clone();
        let err = Closure::once_into_js(move |_: Event| {
            let msg = match err_req.error() {
                Ok(Some(e)) => e.message(),
                _ => "IndexedDB request failed".to_string(),
            };
            let _ = reject.call1(&JsValue::NULL, &JsValue::from_str(&msg));
        });
        req.set_onsuccess(Some(ok.unchecked_ref()));
        req.set_onerror(Some(err.unchecked_ref()));
    }))
}

impl IdbStore {
    /// Open (creating if needed) the database `name` and load all changes.
    pub async fn open(name: &str) -> Result<Self, JsValue> {
        let factory = Reflect::get(&js_sys::global(), &"indexedDB".into())?;
        if factory.is_undefined() || factory.is_null() {
            return Err("IndexedDB is not available in this environment".into());
        }
        // `unchecked_into`: other implementations (fake-indexeddb) are not instances of
        // the browser's IDBFactory class, but have the same methods.
        let factory: IdbFactory = factory.unchecked_into();

        let open_req: IdbOpenDbRequest = factory.open_with_u32(name, DB_VERSION)?;
        let upgrade_req = open_req.clone();
        let upgrade = Closure::once_into_js(move |_: Event| {
            if let Ok(db) = upgrade_req.result() {
                let db: IdbDatabase = db.unchecked_into();
                let params = IdbObjectStoreParameters::new();
                params.set_auto_increment(true);
                // Each fails harmlessly if the store exists (upgrade from version 1).
                let _ = db.create_object_store_with_optional_parameters(STORE, &params);
                let _ = db.create_object_store(META);
                let _ = db.create_object_store(CHUNKS);
            }
        });
        open_req.set_onupgradeneeded(Some(upgrade.unchecked_ref()));
        let db: IdbDatabase = request_future(&open_req).await?.unchecked_into();

        let tx = db.transaction_with_str(STORE)?;
        let rows = request_future(&tx.object_store(STORE)?.get_all()?).await?;
        let mut mem = MemoryStore::new();
        for row in js_sys::Array::from(&rows).iter() {
            let change = codec::decode_change(&Uint8Array::new(&row).to_vec())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            change
                .verify()
                .map_err(|e| JsValue::from_str(&format!("stored change is invalid: {e}")))?;
            mem.put(change)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        let tx = db.transaction_with_str(META)?;
        let meta = tx.object_store(META)?;
        let keys = js_sys::Array::from(&request_future(&meta.get_all_keys()?).await?);
        let values = js_sys::Array::from(&request_future(&meta.get_all()?).await?);
        for (k, v) in keys.iter().zip(values.iter()) {
            let key = k.as_string().ok_or("meta key is not a string")?;
            mem.put_meta(&key, &Uint8Array::new(&v).to_vec())
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        let tx = db.transaction_with_str(CHUNKS)?;
        let store = tx.object_store(CHUNKS)?;
        let keys = js_sys::Array::from(&request_future(&store.get_all_keys()?).await?);
        let values = js_sys::Array::from(&request_future(&store.get_all()?).await?);
        for (k, v) in keys.iter().zip(values.iter()) {
            let id = k
                .as_string()
                .and_then(|h| hex_id(&h))
                .ok_or("chunk key is not a hex ID")?;
            let bytes = Uint8Array::new(&v).to_vec();
            let (scope, data) = split_chunk(&bytes).ok_or("corrupt chunk record")?;
            mem.put_chunk(&id, &scope, data)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        }

        let on_write_error = Closure::<dyn FnMut(Event)>::new(|_: Event| {
            web_sys::console::error_1(&"kith: writing a change to IndexedDB failed".into());
        });
        Ok(Self {
            mem,
            db,
            on_write_error,
        })
    }

    fn write_tx(&self, store: &str) -> Result<web_sys::IdbObjectStore, JsValue> {
        let tx = self
            .db
            .transaction_with_str_and_mode(store, IdbTransactionMode::Readwrite)?;
        let handler = self.on_write_error.as_ref().unchecked_ref();
        tx.set_onerror(Some(handler));
        tx.set_onabort(Some(handler));
        tx.object_store(store)
    }

    fn persist(&self, change: &Change) -> Result<(), JsValue> {
        self.write_tx(STORE)?
            .add(&Uint8Array::from(codec::encode_change(change).as_slice()))?;
        Ok(())
    }
}

fn hex_id(h: &str) -> Option<[u8; 32]> {
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn split_chunk(b: &[u8]) -> Option<(Scope, &[u8])> {
    let n = u16::from_be_bytes(b.get(..2)?.try_into().ok()?) as usize;
    let scope = Scope::parse(std::str::from_utf8(b.get(2..2 + n)?).ok()?).ok()?;
    Some((scope, &b[2 + n..]))
}

impl Store for IdbStore {
    fn put(&mut self, change: Change) -> Result<bool, StoreError> {
        if self.mem.contains(&change.change_id)? {
            return Ok(false);
        }
        // Queue the write first so a synchronous failure leaves memory unchanged.
        self.persist(&change)
            .map_err(|e| StoreError::Backend(js_message(&e)))?;
        self.mem.put(change)
    }

    fn get(&self, id: &ChangeId) -> Result<Option<Change>, StoreError> {
        self.mem.get(id)
    }

    fn contains(&self, id: &ChangeId) -> Result<bool, StoreError> {
        self.mem.contains(id)
    }

    fn history(&self, object: &ObjectId) -> Result<Vec<Change>, StoreError> {
        self.mem.history(object)
    }

    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError> {
        self.mem.all_ids()
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.mem.get_meta(key)
    }

    /// Chunks are kept in memory too (the `Store` API is synchronous), so very large
    /// files cost RAM on the web.
    fn put_chunk(&mut self, id: &[u8; 32], scope: &Scope, data: &[u8]) -> Result<(), StoreError> {
        let mut record = Vec::with_capacity(2 + scope.as_str().len() + data.len());
        record.extend_from_slice(&(scope.as_str().len() as u16).to_be_bytes());
        record.extend_from_slice(scope.as_str().as_bytes());
        record.extend_from_slice(data);
        let key: String = id.iter().map(|b| format!("{b:02x}")).collect();
        self.write_tx(CHUNKS)
            .and_then(|s| {
                s.put_with_key(
                    &Uint8Array::from(record.as_slice()),
                    &JsValue::from_str(&key),
                )
            })
            .map_err(|e| StoreError::Backend(js_message(&e)))?;
        self.mem.put_chunk(id, scope, data)
    }

    fn get_chunk(&self, id: &[u8; 32]) -> Result<Option<(Scope, Vec<u8>)>, StoreError> {
        self.mem.get_chunk(id)
    }

    /// Queued like change writes: durable once the browser commits the transaction.
    /// Transactions on one store commit in order, so a newer state never loses to an
    /// older one.
    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.write_tx(META)
            .and_then(|s| s.put_with_key(&Uint8Array::from(value), &JsValue::from_str(key)))
            .map_err(|e| StoreError::Backend(js_message(&e)))?;
        self.mem.put_meta(key, value)
    }
}
