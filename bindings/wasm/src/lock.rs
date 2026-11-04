//! One owner per IndexedDB database (REQ-PLAT-006).
//!
//! Each `KithClient` keeps the whole store and the MLS group state in memory and
//! writes through to IndexedDB. Two clients on the same database (two tabs) would
//! each advance their own copy of the group state and overwrite each other, which can
//! reuse encryption keys. So `KithClient.open` takes an exclusive Web Lock named after
//! the database and holds it until the client is freed or the page goes away.
//!
//! Where `navigator.locks` does not exist (older Node, very old browsers) there is
//! no guard; the app must make sure itself that only one client is open.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(inline_js = r#"
export function acquireLock(name, wait) {
  const locks = globalThis.navigator && globalThis.navigator.locks;
  if (!locks || typeof locks.request !== "function") return Promise.resolve(undefined);
  return new Promise((resolve, reject) => {
    locks
      .request(name, { mode: "exclusive", ifAvailable: !wait }, (lock) => {
        if (!lock) {
          resolve(null);
          return;
        }
        // Held until the returned promise settles: i.e. until `release` is called.
        return new Promise((release) => resolve(release));
      })
      .catch(reject);
  });
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = acquireLock)]
    fn acquire_lock(name: &str, wait: bool) -> js_sys::Promise;
}

/// A held lock; released on drop.
pub struct TabLock {
    release: js_sys::Function,
}

impl Drop for TabLock {
    fn drop(&mut self) {
        let _ = self.release.call0(&JsValue::NULL);
    }
}

/// Take the lock for database `db_name`. `Ok(None)`: this environment has no Web
/// Locks, so there is no guard. With `wait` false, an error says the database is open
/// elsewhere; with `wait` true the future resolves once the other owner is gone.
pub async fn acquire(db_name: &str, wait: bool) -> Result<Option<TabLock>, JsError> {
    let name = format!("kith-db:{db_name}");
    let v = wasm_bindgen_futures::JsFuture::from(acquire_lock(&name, wait))
        .await
        .map_err(|e| JsError::new(&crate::idb::js_message(&e)))?;
    if v.is_undefined() {
        return Ok(None);
    }
    if v.is_null() {
        return Err(JsError::new(&format!(
            "the database {db_name:?} is already open in another tab, window or client; \
             close it there, or call open with waitForLock = true to wait for it"
        )));
    }
    Ok(Some(TabLock {
        release: v.unchecked_into(),
    }))
}
