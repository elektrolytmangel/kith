# Integrating kith into apps

All platforms expose the same `KithClient` API: `deviceId`, `create`, `edit`,
`history`, and `secretKey` / `withSecretKey` to keep the device identity across
restarts (store the key in the platform's secure storage).
`generateSecretKey()` and `KithClient.open(...)` also persist the data: in a SQLite
file on Swift and Kotlin (`dbPath`), in IndexedDB on the web (`dbName`, returns a
Promise). `KithClient()` stays ephemeral. Invitations (links/QR) and permissions come in later phases.

## Documents

`create`/`edit` store opaque bytes: concurrent edits of one object stay a fork that
the app resolves. For JSON-like data use **documents**, which merge on their own
(Automerge, [ADR 0003](../adr/0003-merge-automerge-default-pluggable.md)):

```ts
const id = client.createDocument("acme.todo", JSON.stringify({ title: "Buy milk" }));
client.updateDocument(id, JSON.stringify({ done: true, title: null })); // RFC 7396 merge patch
const todo = JSON.parse(client.documentJson(id)); // merged state, all devices' edits
```

A patch sets the keys it names, removes keys set to `null` and merges nested objects.
Edits of different keys on different devices all survive; for the same key every
device picks the same winner. Arrays are replaced as a whole. The same three calls
exist on Swift/Kotlin (`createDocument(objectType:json:)`, `updateDocument(objectId:patch:)`,
`documentJson(objectId:)`) and in Rust (`Client::create_document`, feature `automerge`).
Re-read `documentJson` on `received` / `syncReceived` events. Documents add about
1.2 MB to the web package (3.2 MB `.wasm` uncompressed).

## Organizations and encryption

Everything a device sends through the relay is end-to-end encrypted for the
organization's MLS group ([ADR 0004](../adr/0004-mls-openmls-rustcrypto.md)); the
relay sees only routing data, sizes and timing. A device must be in the group to send
or read:

1. The device that creates the organization calls `createGroup(org)` once.
2. A new device connects and sends a join request to an online member
   (`requestJoin(memberDeviceId)`, using an ID from a `presence` event).
3. The member gets a `joinRequested` event with a `keyPackage`; the app decides
   (for example after the user confirms the device) and calls `addMember(keyPackage)`.
4. The new device gets `joined` and downloads the history from a peer on its own.

Devices that missed group changes while offline catch up automatically
(`epochBehind`, `commitsApplied` events); one that missed more than the last 256
changes is re-added automatically by an online member (`reAddRequested`,
`memberReAdded`). If two devices change the group at the same moment, the group
forks briefly; kith picks the same winner on every device and re-adds the others
(`fork` event), with no app action needed. A device that the losing change had
just added shows up as a new `joinRequested` and needs approval again. Call `rotateKey()` now and then (for example weekly) and
`removeMember(deviceId)` to revoke a device. The group state contains secrets and is
saved with the data (`KithClient.open`), so keep the database in app-private storage.
Until phase 5 (invitations) both devices must be online to add a device.

Every package is a GitHub Release asset:
`https://github.com/elektrolytmangel/kith/releases/download/vX.Y.Z/<asset>`. The repository
is public, so no token is needed (for private projects started from this template, see
[Releasing](releasing.md#if-your-repository-is-private)).

## Web

```sh
npm install https://github.com/elektrolytmangel/kith/releases/download/v0.1.0-alpha.1/kith-wasm-0.1.0-alpha.1.tgz
```

```ts
import init, { KithClient } from "@elektrolytmangel/kith-wasm";

await init();
const client = new KithClient();
const id = client.create("acme.note", new TextEncoder().encode("hello"));
client.edit(id, new TextEncoder().encode("hello world"));
```

Persist data and identity in IndexedDB. Save the key once (for example wrapped with
the Web Crypto API; never log it) and reopen the same database later:

```ts
const key = generateSecretKey();                // first launch only; store it
const client = await KithClient.open("my-app", key); // Promise
```

Changes are kept in memory and written through to IndexedDB (database `my-app`).
`new KithClient()` stays ephemeral.

Live sync with other devices through a relay (see [Relay](#relay) below):

```ts
client.createGroup("my-org"); // first device only (see "Organizations and encryption")
client.connect("wss://relay.example.com/v1/ws", "my-org", (e) => {
  // e.type: "received" | "rejected" | "presence" | "receipt" | "joinRequested" | "joined" | ...
  if (e.type === "received") render(e.objectId); // the change is already decrypted, validated and stored
  if (e.type === "joinRequested" && userApproves(e.from)) client.addMember(e.keyPackage);
});
client.create("acme.note", bytes); // now also broadcast (encrypted) to the other online devices

// On a new device: client.connect(...), then client.requestJoin(memberId) and wait for "joined".
```

Catch up on changes made while this device was offline (and download the history on a
new device) by asking one online peer. The two compare their change sets in a few small rounds
(`syncCompared`: how many changes go each way), then the missing changes arrive as `syncReceived` events:

```ts
client.catchUp(); // after connecting, once a "presence" event shows another device
```

Live updates only reach devices that are online at the same time. Node 22+ has a global
`WebSocket`; older Node needs a polyfill.

Bundlers: build with `scripts/build-wasm.sh bundler` for webpack and Vite
without an `init()` call. Electron renderer processes work like the web;
for the main process, prefer the Rust crate through a native module.

## iOS / macOS

Unzip `kith-swift-package.zip` from the release into your project and add it
as a local package (Xcode: *Add Package Dependencies → Add Local*). Its
`Package.swift` fetches `KithFFI.xcframework.zip` from the same release and
verifies the checksum.

```swift
import Kith

let client = KithClient()
let change = try client.create(type: "acme.note", text: "hello")
let history = try client.history(objectId: change.objectId)
```

Live sync with other devices (`RelayConnection` wraps `URLSessionWebSocketTask`; the
protocol logic is in Rust):

```swift
try client.createGroup(org: "my-org")   // first device only
let conn = RelayConnection(client: client, url: URL(string: "wss://relay.example.com/v1/ws")!,
                           org: "my-org", onEvent: { event in
    if case .received(_, _, let objectId, _, _) = event { /* decrypted, validated, stored */ }
    if case .joinRequested(_, _, let keyPackage) = event { try? conn.addMember(keyPackage: keyPackage) }
})
conn.start()
// On a new device: conn.requestJoin(to: memberId), then wait for `.joined`.
let change = try client.create(type: "acme.note", text: "hi")
conn.broadcast(change)   // to the other online devices
```

Call `conn.catchUp()` once a `.presence` event shows another device to download what this
device missed (or the whole history on a new device); answers arrive as `.syncReceived`
events. Live updates only reach devices online at the same time.

Keep the device key in the Keychain: after the first launch save
`client.secretKey()` (32 bytes), and on later launches restore the same device
identity with `try KithClient.withSecretKey(secretKey: data)`.

## Android

```kotlin
// Copy kith-android-0.1.0-alpha.1.aar from the release into app/libs/.
dependencies {
    implementation(files("libs/kith-android-0.1.0-alpha.1.aar"))
    // A local AAR doesn't carry its dependencies; the generated code needs JNA.
    implementation("net.java.dev.jna:jna:5.15.0@aar")
}
```

```kotlin
import dev.kith.*

val client = KithClient()
val change = client.create("acme.note", "hello")
val history = client.history(change.objectId)
```

Live sync with other devices: you own the WebSocket (here OkHttp), `RelaySession`
(Rust) does the protocol:

```kotlin
client.createGroup("my-org")            // first device only
val session = client.relaySession("my-org")
val ws = okHttp.newWebSocket(Request.Builder().url("wss://relay.example.com/v1/ws").build(),
    object : WebSocketListener() {
        override fun onOpen(ws: WebSocket, r: Response) { ws.send(session.hello().toByteString()) }
        override fun onMessage(ws: WebSocket, bytes: ByteString) {
            val out = session.receive(bytes.toByteArray())
            out.replies.forEach { ws.send(it.toByteString()) }
            out.event?.let { /* RelayEvent.Received, .JoinRequested, .Joined, ... */ }
            // JoinRequested: session.addMember(keyPackage).forEach { ws.send(it.toByteString()) }
        }
    })
// after create/edit:
ws.send(session.broadcast(change.changeId).toByteString())
```

Catch up with `ws.send(session.catchUp().toByteString())` once a `RelayEvent.Presence` shows
another device (answers come back through `receive` as `RelayEvent.SyncReceived`). A new
device sends `session.joinRequest(memberId)` and waits for `RelayEvent.Joined`. Live updates
only reach online devices.

Keep the device key in the Android Keystore: save `client.secretKey()` (encrypted with a
Keystore key) and restore with `KithClient.withSecretKey(bytes)`.

## Rust desktop, Tauri, headless

```toml
[dependencies]
kith-client = { git = "https://github.com/elektrolytmangel/kith", tag = "v0.1.0-alpha.1" }
```

```rust
use kith_client::{Client, DeviceKey, MemoryStore, ObjectType};

let mut client = Client::new(DeviceKey::generate(), MemoryStore::new())?;
let change = client.create(ObjectType::new("acme.note"), b"hello".to_vec())?;
client.create_group("my-org")?; // or join: join_request_frame / add_member
let frame = client.broadcast_frame("my-org", &change)?; // encrypted; send it to the relay
```

`kith_net::LiveClient` (native) does the WebSocket part: `create`/`edit` broadcast,
`request_join`, `add_member`, `catch_up`, `next_event`.

The always-on client (phase 7) is a headless Rust binary built this way.

## Relay

```sh
# Binary from the release (Linux/macOS/Windows, x86_64 and arm64)
curl -fsSL https://github.com/elektrolytmangel/kith/releases/download/v0.1.0-alpha.1/kith-relay-x86_64-unknown-linux-gnu.tar.gz | tar -xz
./kith-relay

# or as a container, built from source
docker build -f apps/relay-server/Dockerfile -t kith-relay . && docker run -p 8080:8080 kith-relay

# or embed kith_relay::RoutingTable in your own server
```

| Env | Default | |
| --- | --- | --- |
| `KITH_RELAY_ADDR` | `0.0.0.0:8080` | listen address |
| `KITH_RELAY_AUTH_TIMEOUT_SECS` | `10` | time a new connection has to authenticate |
| `RUST_LOG` | `info` | log filter |

Devices authenticate by signing a challenge with their key (`hello` → `challenge` →
`auth`; Rust clients use `kith_client::hello_frame` and `auth_frame`). The relay
does not check organization membership proofs yet (REQ-RELAY-004, needs the org
root of trust from phase 5): any device with a valid key can join any org id.
Message bodies are end-to-end encrypted, so a relay operator cannot read data, but
without membership proofs anyone can connect to an org id and see its metadata or
flood it. Don't expose the relay publicly until then.
