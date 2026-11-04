// Browser helpers that ship next to the generated bindings.
//   import { loadOrCreateDeviceKey, requestPersistentStorage } from "@<scope>/kith-wasm/kith-web.js";
// No dependencies. All functions need a browser, worker or Node with `crypto.subtle`
// and `indexedDB`.

/**
 * Ask the browser not to evict this origin's storage (IndexedDB holds the data and
 * the group keys of this device). Safari evicts script-writable storage after 7 days
 * without use unless the app is installed or storage is persistent; losing it means
 * the device is gone. Returns whether storage is persistent now. Call it after a user
 * gesture or when the user starts to rely on the app.
 */
export async function requestPersistentStorage() {
  const s = globalThis.navigator && globalThis.navigator.storage;
  if (!s || typeof s.persist !== "function") return false;
  try {
    return (await s.persisted()) || (await s.persist());
  } catch {
    return false;
  }
}

/** `{usage, quota}` in bytes, or `null` where the browser cannot say. */
export async function storageEstimate() {
  const s = globalThis.navigator && globalThis.navigator.storage;
  if (!s || typeof s.estimate !== "function") return null;
  try {
    const { usage, quota } = await s.estimate();
    return { usage, quota };
  } catch {
    return null;
  }
}

const KEY_STORE = "keys";

function openKeyDb(name) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(`kith-keys:${name}`, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(KEY_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * The 32-byte device secret key of `name`, created on first use with `generate`
 * (pass `generateSecretKey` from the bindings) and kept in IndexedDB *encrypted* with
 * a non-extractable AES-GCM `CryptoKey`. A copy of the IndexedDB files, a backup of the
 * browser profile or a stray dump then contains no usable device key. It does not
 * protect against script running in your page (XSS can ask for the key as the app
 * does): keep a strict Content-Security-Policy.
 *
 * @param {string} name   one per app and user, e.g. "my-app"
 * @param {() => Uint8Array} generate
 * @returns {Promise<Uint8Array>}
 */
export async function loadOrCreateDeviceKey(name, generate) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error("kith-web: crypto.subtle is not available (needs a secure context)");
  const db = await openKeyDb(name);
  try {
    const read = () => request(db.transaction(KEY_STORE).objectStore(KEY_STORE).get("device"));
    const existing = await read();
    if (existing) {
      const plain = await subtle.decrypt(
        { name: "AES-GCM", iv: existing.iv },
        existing.wrapKey,
        existing.ciphertext,
      );
      return new Uint8Array(plain);
    }
    const secret = generate();
    const wrapKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, secret);
    const tx = db.transaction(KEY_STORE, "readwrite");
    // add(): if another tab created a key meanwhile, this fails and we use theirs.
    const store = tx.objectStore(KEY_STORE);
    const added = new Promise((resolve) => {
      const r = store.add({ wrapKey, iv, ciphertext }, "device");
      r.onsuccess = () => resolve(true);
      r.onerror = (e) => {
        e.preventDefault();
        resolve(false);
      };
    });
    if (await added) return new Uint8Array(secret);
    return loadOrCreateDeviceKey(name, generate);
  } finally {
    db.close();
  }
}

/**
 * Forget the stored device key of `name`. The device identity is gone unless the app
 * has a backup (`exportBackup`).
 */
export async function deleteDeviceKey(name) {
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(`kith-keys:${name}`);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}
