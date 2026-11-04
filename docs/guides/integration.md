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
or read, and devices join by invitation ([ADR 0005](../adr/0005-org-root-key-certificates-invites.md)):

1. The first device calls `createOrg()`. It returns the **org ID**, the public key of a
   new org root key that this device keeps. The device is the first admin. Keep a
   display name for the org in your own data; the ID is 64 hex characters.
2. An admin calls `createInvite(org, relayUrl, ttlSeconds)` and shares the link (QR
   code, message). It works once and expires. Treat it like a password.
3. The new device reads the link (`parseInvite(link)` gives `org` and `relay`), connects
   to that relay and org, and calls `claimInvite(link)`, which returns a 6-digit code to
   show. Until it is admitted the relay treats it as *pending*: it can only claim.
4. The admin that issued the invite gets `inviteClaimed { from, code }`. The app can
   ask the user to compare the codes on both screens, then calls `acceptClaim(from)` (or
   `rejectClaim(from)`). Only that admin can accept, and it must be online.
5. The new device gets `joined` with its membership certificate, announces itself
   to the relay with it, and downloads the history from a peer on its own.

The creator can make another member an admin with `grantAdmin(deviceId)`; that device
gets `certificateUpdated { admin: true }` and can then invite too.

### Scopes

Every change belongs to a scope: the org, or `local` for data created before the
device joins an org (it is never synced). `create` and `createDocument` use the org
this device belongs to, so most apps never name a scope. A device in several orgs
uses `createIn(org, type, payload)` (Rust: `create_in`, `create_document_in`); each
org's data only ever syncs with that org ([ADR 0007](../adr/0007-scope-in-change-envelope.md)).

### Subgroups (read-restricted data)

Data that only some members may read goes into a subgroup, with its own encryption
keys ([ADR 0008](../adr/0008-subgroups.md)):

```ts
client.createSubgroup("finance", [aliceId, bobId]);   // admins; this device runs it
client.createIn(`${org}/finance`, "acme.ledger", bytes); // only finance members get it
client.mySubgroups(org);                                 // ["finance"] on members
client.setSubgroupMembers("finance", [aliceId]);         // bob loses access to new data
```

Members join automatically once they see the subgroup in the policy, while the
device that created it is online. `catchUp()` also catches up the subgroups.

### Roles and write permissions

Every org has a policy that all devices enforce on every change
([ADR 0006](../adr/0006-policy-object-roles-revocation.md)). Roles are `viewer`,
`editor` (the default for members) and `admin`:

```ts
client.setWriteRule("config", "admin");   // only admins write objects of type "config"
client.setRole(deviceId, "viewer");      // read-only; earlier changes stay valid
client.roleOf(org, deviceId);            // "viewer" | "editor" | "admin" | undefined (revoked)
client.removeMember(deviceId);           // out of the group and revoked
```

A write the policy forbids fails locally (`not allowed`). A forbidden change from a
modified app arrives as a `rejected` event and never shows up in history or documents.
When a device is revoked, its changes that the admin had already seen stay; anything
else it made (for example offline) is rejected on every device, and so are edits that
build only on those changes.

Devices that missed group changes while offline catch up automatically
(`epochBehind`, `commitsApplied` events); one that missed more than the last 256
changes is re-added automatically by an online member (`reAddRequested`,
`memberReAdded`). If two devices change the group at the same moment, the group
forks briefly; kith picks the same winner on every device and re-adds the others
(`fork` event), with no app action needed. A device that the losing change had
just added needs a new invite. Call `rotateKey()` now and then (for example weekly) and
`removeMember(deviceId)` to revoke a device. The group state, the org root key and open
invites contain secrets and are saved with the data (`KithClient.open`), so keep the
database in app-private storage.

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
const org = client.createOrg(); // first device only (see "Organizations and encryption")
client.connect("wss://relay.example.com/v1/ws", org, (e) => {
  // e.type: "received" | "rejected" | "presence" | "receipt" | "inviteClaimed" | "joined" | ...
  if (e.type === "received") render(e.objectId); // the change is already decrypted, validated and stored
  if (e.type === "inviteClaimed" && userConfirmsCode(e.code)) client.acceptClaim(e.from);
});
client.create("acme.note", bytes); // now also broadcast (encrypted) to the other online devices
const link = client.createInvite(org, "wss://relay.example.com/v1/ws", 24 * 3600);

// On the new device:
const { org: o, relay } = KithClient.parseInvite(link);
newClient.connect(relay, o, onEvent);
showCode(newClient.claimInvite(link)); // then wait for "joined"
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
let org = try client.createOrg()   // first device only
let conn = RelayConnection(client: client, url: URL(string: "wss://relay.example.com/v1/ws")!,
                           org: org, onEvent: { event in
    if case .received(_, _, let objectId, _, _) = event { /* decrypted, validated, stored */ }
    if case .inviteClaimed(_, let from, let code) = event, userConfirms(code) { try? conn.acceptClaim(from) }
})
conn.start()
let link = try client.createInvite(org: org, relay: "wss://relay.example.com/v1/ws", ttlSeconds: 86400)
// On the new device: let info = try parseInvite(link: link); connect to info.relay / info.org,
// then `let code = try conn.claim(link)` and wait for `.joined`.
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
val org = client.createOrg()           // first device only
val session = client.relaySession(org)
val ws = okHttp.newWebSocket(Request.Builder().url("wss://relay.example.com/v1/ws").build(),
    object : WebSocketListener() {
        override fun onOpen(ws: WebSocket, r: Response) { ws.send(session.hello().toByteString()) }
        override fun onMessage(ws: WebSocket, bytes: ByteString) {
            val out = session.receive(bytes.toByteArray())
            out.replies.forEach { ws.send(it.toByteString()) }
            out.event?.let { /* RelayEvent.Received, .InviteClaimed, .Joined, ... */ }
            // InviteClaimed: session.acceptClaim(from).forEach { ws.send(it.toByteString()) }
        }
    })
// after create/edit:
ws.send(session.broadcast(change.changeId).toByteString())
```

Catch up with `ws.send(session.catchUp().toByteString())` once a `RelayEvent.Presence` shows
another device (answers come back through `receive` as `RelayEvent.SyncReceived`). A new
device opens the session for `parseInvite(link).org`, sends `session.claim(link).frame` after
the handshake and waits for `RelayEvent.Joined`. Live updates only reach online devices.

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
`auth`; Rust clients use `kith_client::hello_frame` and `auth_frame`). Then they
announce orgs with a membership certificate chain, which the relay checks against
the org ID (the org root public key) without storing anything (REQ-RELAY-004). A
device without a certificate is *pending*: it may only send invite claims (the relay
passes them to the org's online admins) and receive direct messages. A removed device
keeps a valid certificate until revocation lands (phase 6) but cannot decrypt
anything. Message bodies are end-to-end encrypted, so the operator sees only
metadata. There are no rate limits yet (phase 8).
