# Web apps in production

What a browser app has to know beyond the [quick start](integration.md#web). A runnable
example is [`examples/web-vite`](../../examples/web-vite) (built in CI).

## One tab per database

`KithClient.open` keeps the whole store and the MLS group state in memory and writes
through to IndexedDB. Two clients on one database would each advance their own copy of
the group state and overwrite each other, which can reuse encryption keys. So `open`
takes an **exclusive Web Lock** (`navigator.locks`) named after the database and holds it
until the client is freed (`client.free()`) or the page closes.

```ts
try {
  client = await KithClient.open("my-app", key);
} catch (e) {
  // "the database "my-app" is already open in another tab, window or client ..."
  showBanner("This app is already open in another tab.");
}
// or become the active tab as soon as the other one closes:
client = await KithClient.open("my-app", key, true);
```

Pick one: fail fast and tell the user, or wait (leader election; the waiting tab takes
over). If an app wants several tabs to be usable at once, run the client in one
`SharedWorker` or a leader tab and let the other tabs talk to it with `postMessage` or
`BroadcastChannel`. Where `navigator.locks` is missing (Node before 24, very old
browsers) there is no guard: make sure yourself that only one client is open.
Use a different database name per user on a shared browser.

## Connection

`connect` reconnects by itself, 1 s after a drop, doubling up to 30 s (with jitter), and
immediately when the browser fires `online`, until you call `disconnect()`.

| Event | Meaning |
| --- | --- |
| `connected` | handshake started on a new socket |
| `closed` | the socket closed |
| `reconnecting` (`attempt`, `delayMs`) | next try is scheduled |
| `error` | socket error (a `closed` follows) |

Changes made while offline are stored locally and not queued on the socket. After
`connected`, wait for a `presence` event with another device online and call
`catchUp()` (the example does this): both sides exchange what they missed. Background
tabs throttle timers, so a reconnect can take up to a minute there.

The relay does not check the `Origin` header: any page can open a socket, but it still
has to authenticate with a device key and cannot read anything. Add your relay to the
`connect-src` of your Content-Security-Policy.

## Listing data

`client.objects(type?)` returns `{objectId, objectType, scope, author, createdMs}` for every
object the device knows, oldest first. Build the view with it at start-up, then update
from `received` / `syncReceived` events. It walks the whole store, so don't call it per
event on large stores.

## Keys and storage

`kith-web.js` ships in the package (`import … from "@<scope>/kith-wasm/kith-web.js"`):

- `loadOrCreateDeviceKey(name, generateSecretKey)` keeps the 32-byte device key in
  IndexedDB **encrypted with a non-extractable AES-GCM key**. A copy of the browser
  profile or of the IndexedDB files then holds no usable device key. It does not stop
  script running in your page (XSS can ask for the key like your app does): use a strict
  CSP.
- `requestPersistentStorage()` asks the browser not to evict your data. Safari deletes
  script-written storage after 7 days without a visit unless the site is installed to
  the home screen or storage is persistent. Losing IndexedDB means losing the device
  (its identity and group keys). Call it once the user relies on the app.
- `storageEstimate()` gives usage and quota.
- Offer backups: `exportBackup(passphrase)` and `KithClient.restoreBackup`. Restore only
  when the original device is gone (see [backups](integration.md#backups)).

The org and group state in IndexedDB is sealed with a key derived from the device key (ADR 0021),
so a copy of the database alone is not enough; the browser itself protects it by origin only.
Anything your own page can read, an XSS can read too. See the [threat model](threat-model.md).

## Content-Security-Policy

The package needs `'wasm-unsafe-eval'` in `script-src` and nothing else:

```
default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' wss://relay.example.com
```

No `'unsafe-eval'`, no inline scripts. The browser tests run under exactly this policy.

## Bundlers and TypeScript

The package is built for `--target web` (call `await init()` first; the `.wasm` is loaded
with `new URL(…, import.meta.url)`, which Vite, webpack 5 and esbuild-based tools handle).
For webpack and Vite without `init()` build with `scripts/build-wasm.sh bundler`. Type
definitions (`kith.d.ts`, `kith-web.d.ts`) are included. With Vite keep the package out of
pre-bundling: `optimizeDeps: { exclude: ["@<scope>/kith-wasm"] }`.

## Size and memory

Measured in Chromium (`KITH_MEASURE=… node bindings/wasm/tests/browser/run.mjs`), release build,
200-byte changes on a developer machine:

| Changes | Create (each) | Open from IndexedDB | wasm memory | Storage |
| --- | --- | --- | --- | --- |
| 10 000 | 80 µs | 1.1 s | 10 MiB | 4 MiB |
| 50 000 | 83 µs | 5.9 s | 38 MiB | 9 MiB |

Opening grows linearly (about 0.12 ms and 0.75 KiB per change); 100 000 changes would take
roughly 12 s and 75 MiB (extrapolated, not measured).

- **Download:** `kith_bg.wasm` is about 3.4 MiB, 1.3 MiB with gzip or brotli. Serve it compressed
  and with long-lived caching (the file name changes with the version).
- **Memory:** the whole history is held in memory, roughly 0.75 KiB per change. Files also sit
  in memory while the page is open. Until an admin compacts (`setRetention` + `compact`, see [history compaction](integration.md#history-compaction))
  nothing is dropped: plan for at most a few ten thousand changes per device. Prefer documents (merged
  edits) over one object per keystroke.
- **Start-up:** opening reads every change from IndexedDB and verifies its signature. Do it once,
  show UI first, and avoid reloading the page needlessly.
