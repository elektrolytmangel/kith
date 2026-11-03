# Integrating kith into apps

All platforms expose the same `KithClient` API: `deviceId`, `create`, `edit`
and `history`. Sync, encryption and invitations will be added in later phases.

Every package is a GitHub Release asset:
`https://github.com/OWNER/kith/releases/download/vX.Y.Z/<asset>`. For a private
repository, downloads need a GitHub token (see [Releasing](releasing.md#private-repositories)).

## Web

```sh
npm install https://github.com/OWNER/kith/releases/download/v0.1.0/kith-wasm-0.1.0.tgz
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

Keep the device key in the Keychain. This needs the key-seed constructor
planned for phase 1.

## Android

```kotlin
// Copy kith-android-0.1.0.aar from the release into app/libs/.
dependencies {
    implementation(files("libs/kith-android-0.1.0.aar"))
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

## Rust desktop, Tauri, headless

```toml
[dependencies]
kith-client = { git = "https://github.com/OWNER/kith", tag = "v0.1.0" }
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
curl -fsSL https://github.com/OWNER/kith/releases/download/v0.1.0/kith-relay-x86_64-unknown-linux-gnu.tar.gz | tar -xz
./kith-relay

# or as a container, built from source
docker build -f apps/relay-server/Dockerfile -t kith-relay . && docker run -p 8080:8080 kith-relay

# or embed kith_relay::RoutingTable in your own server
```

| Env | Default | |
| --- | --- | --- |
| `KITH_RELAY_ADDR` | `0.0.0.0:8080` | listen address |
| `RUST_LOG` | `info` | log filter |

Until REQ-RELAY-004 (device authentication) is implemented, don't expose the
relay publicly.
