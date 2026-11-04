# Integrating kith into apps

All platforms expose the same `KithClient` API: `deviceId`, `create`, `edit`,
`history`, and `secretKey` / `withSecretKey` to keep the device identity across
restarts (store the key in the platform's secure storage).
`generateSecretKey()` and `KithClient.open(...)` also persist the data: in a SQLite
file on Swift and Kotlin (`dbPath`), in IndexedDB on the web (`dbName`, returns a
Promise). `KithClient()` stays ephemeral. Sync, encryption and invitations will be added in later phases.

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

Keep the device key in the Android Keystore: save `client.secretKey()` (encrypted with a
Keystore key) and restore with `KithClient.withSecretKey(bytes)`.

## Rust desktop, Tauri, headless

```toml
[dependencies]
kith-client = { git = "https://github.com/elektrolytmangel/kith", tag = "v0.1.0-alpha.1" }
```

```rust
use kith_client::{Client, DeviceKey, MemoryStore, ObjectType};

let mut client = Client::new(DeviceKey::generate(), MemoryStore::new());
let change = client.create(ObjectType::new("acme.note"), b"hello".to_vec())?;
```

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
Don't expose the relay publicly until then.
