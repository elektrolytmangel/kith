# Integrating kith into apps

All platforms expose the same `KithClient` API: `deviceId`, `create`, `edit`
and `history`. Sync, encryption and invitations will be added in later phases.

## Web

```sh
npm install @OWNER/kith-wasm   # set the registry for @OWNER in .npmrc if using GitHub Packages
```

```ts
import init, { KithClient } from "@OWNER/kith-wasm";

await init();
const client = new KithClient();
const id = client.create("acme.note", new TextEncoder().encode("hello"));
client.edit(id, new TextEncoder().encode("hello world"));
```

Bundlers: build with `scripts/build-wasm.sh bundler` for webpack and Vite
without an `init()` call. Electron renderer processes work like the web;
for the main process, prefer the Rust crate through a native module.

## iOS / macOS

Add the Swift package, either from the mirror repo (`SWIFT_PACKAGE_REPO`) or by
unpacking `kith-swift-package.zip` from the GitHub release.

```swift
import Kith

let client = KithClient()
let change = try client.create(type: "acme.note", text: "hello")
let history = try client.history(objectId: change.objectId)
```

Keep the device key in the Keychain. This needs the key-seed constructor
planned for phase 1.

## Android

```kotlin
// settings.gradle.kts → repositories { maven("https://maven.pkg.github.com/OWNER/kith") { credentials { ... } } }
dependencies { implementation("dev.kith:kith-android:0.1.0") }
```

```kotlin
import dev.kith.*

val client = KithClient()
val change = client.create("acme.note", "hello")
val history = client.history(change.objectId)
```

## Rust desktop, Tauri, headless

```toml
[dependencies]
kith-client = "0.1"
```

```rust
use kith_client::{Client, DeviceKey, MemoryStore, ObjectType};

let mut client = Client::new(DeviceKey::generate(), MemoryStore::new());
let change = client.create(ObjectType::new("acme.note"), b"hello".to_vec())?;
```

The always-on client (phase 7) is a headless Rust binary built this way.

## Relay

```sh
docker run -p 8080:8080 ghcr.io/OWNER/kith-relay:0.1
# or embed kith_relay::RoutingTable in your own server
```

| Env | Default | |
| --- | --- | --- |
| `KITH_RELAY_ADDR` | `0.0.0.0:8080` | listen address |
| `RUST_LOG` | `info` | log filter |

Until REQ-RELAY-004 (device authentication) is implemented, don't expose the
relay publicly.
