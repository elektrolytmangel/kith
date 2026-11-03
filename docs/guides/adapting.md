# Adapting kith to a new project

There are two ways to reuse this repository. Pick one.

## A. Use the published packages (recommended)

Your app depends on the released artifacts, and this repository stays the one
place where the protocol evolves. Every app gets fixes by bumping a version.

| Platform | Add |
| --- | --- |
| Web / Electron / Node | `npm install` the release's `kith-wasm-X.Y.Z.tgz` ([web guide](integration.md#web)) |
| iOS / macOS | Swift package from the release ([Apple guide](integration.md#ios--macos)) |
| Android | the release's `kith-android-X.Y.Z.aar` ([Android guide](integration.md#android)) |
| Rust desktop / Tauri / servers | `kith-client` as a git dependency on tag `vX.Y.Z` ([Rust guide](integration.md#rust-desktop-tauri-headless)) |
| Relay | release binary, or `docker build -f apps/relay-server/Dockerfile .` |

You customize through the extension points below, not by forking.

## B. Start a new product from this template

Use this when you want a separately branded and versioned sync stack.

1. On GitHub, *Use this template*. Mark this repository as a template under
   Settings → General first.
2. Rebrand it:
   ```sh
   python3 scripts/rename.py --name acme-sync --owner acme-corp --kotlin-package com.acme.sync
   cargo build && python3 scripts/reqs.py --write
   ```
   This renames crates, directories, the Swift module (`AcmeSync`, `AcmeSyncFFI`),
   the Kotlin package, npm scope, Docker image, env vars (`ACME_SYNC_RELAY_ADDR`)
   and the `OWNER` placeholders.
3. Set the license in `Cargo.toml` and add `LICENSE` files.
4. Fill in `CODEOWNERS`. Optionally set the repository variable `NPM_SCOPE`
   (default: the repository owner).
5. Replace `docs/requirements/*.md` with your product's requirements, or keep
   them and add new areas. Keep the IDs stable after that.

## Extension points

Generic code stays in the library. App-specific behaviour plugs in here:

| Need | Extension point | Where |
| --- | --- | --- |
| Your own data types | `ObjectType` tag + opaque payload bytes (Automerge doc, JSON, protobuf...) | `kith-core` |
| Storage backend (SQLite, IndexedDB, Core Data...) | `Store` trait | `kith-store` |
| Key storage (Keychain, Android Keystore, secure enclave) | `Signer` trait | `kith-core` |
| Transport (relay WebSocket, QUIC, WebRTC, Bluetooth) | `Transport` trait | `kith-client` |
| Group encryption backend / test double | `GroupCrypto` trait | `kith-crypto` |
| Relay inside your own server (auth, metrics, hosting) | `RoutingTable` | `kith-relay` |
| Permission rules per type | policy object (phase 6) | `kith-client` |

Rules of thumb:

- Logic belongs in Rust crates, so every platform validates and merges the
  same way (REQ-PLAT-001). Bindings only convert types.
- Don't fork the protocol per app. If an app needs a protocol change, write a
  requirement and an ADR, and ship it here.
- Prefix app object types with a namespace (`acme.todo`, `acme.config`) so
  different apps can share an organization without collisions.
