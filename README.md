# kith

Local-first, end-to-end encrypted sync for apps. Clients hold all data and sync
from each other through a relay that stores nothing.

- **Library** for web (WASM/npm), iOS/macOS (Swift Package), Android (AAR),
  and desktop/Rust (crates).
- **Generic relay** and **always-on client** as container images (GitHub Packages, see the
  [deployment guide](docs/guides/deployment.md)), or the relay as an embeddable Rust crate.
- **Requirements as code**, with traceability checked in CI.

> `kith` is a working name. `scripts/rename.py` rebrands the whole repository
> in one command (see [Adapting](docs/guides/adapting.md)).

Design: [docs/design/0001-local-first-e2ee-sync.md](docs/design/0001-local-first-e2ee-sync.md)

## Repository layout

```
crates/                    Rust libraries (all logic lives here)
  kith-core/               ids, signed hash-linked change envelope. Pure, no I/O
  kith-protocol/           client ↔ relay wire frames
  kith-crypto/             device keys (Ed25519), MLS groups (OpenMLS)
  kith-store/              Store trait; in-memory, SQLite, byte codec
  kith-sync/               sans-IO catch-up / reconciliation
  kith-merge/              Merger trait + Automerge merger (concurrent edits)
  kith-client/             high-level SDK apps embed (sans-IO live sync: handle_frame)
  kith-net/                native WebSocket client: relay connection + live sync
  kith-relay/              RAM-only routing table, embeddable
apps/
  relay-server/            standalone WebSocket relay + Dockerfile
  always-on/               headless always-on member (kith-always-on)
bindings/                  thin wrappers, no logic
  ffi/                     UniFFI → Swift + Kotlin
  swift/                   Swift Package (iOS/macOS)
  kotlin/                  Android library (Gradle, Maven publish)
  wasm/                    wasm-bindgen → npm package
examples/
  two-devices/             two clients edit offline, then catch up
docs/
  design/                  design documents
  requirements/            requirements (REQ-…) + generated traceability matrix
  adr/                     architecture decision records
  guides/                  getting started, threat model, integration, deployment, adapting, development, releasing
scripts/                   build, codegen, requirements, rename
.github/                   CI, release, issue/PR templates, dependabot
```

How the pieces depend on each other:

```
            apps (Swift / Kotlin / JS / Rust)
                │            │             │
         bindings/ffi   bindings/wasm      │
                └──────┬─────┘             │
                   kith-client ◄───────────┘
        ┌──────────┬───┴──────┬──────────┐
   kith-store  kith-sync  kith-merge  kith-crypto  kith-protocol ◄── kith-relay ◄── apps/relay-server
        └──────────┴────┬─────┘
                    kith-core
```

## Quick start

```sh
cargo test --workspace                 # all tests
cargo run -p example-two-devices       # offline edits + catch-up demo
cargo run -p kith-relay-server         # relay on :8080 (GET /healthz, WS /v1/ws)
python3 scripts/reqs.py                # requirements check
```

Platform packages: `scripts/build-wasm.sh`, `scripts/build-swift.sh` (macOS),
`scripts/build-android.sh` (NDK). See [Development](docs/guides/development.md).

## Packages

Pushing tag `vX.Y.Z` attaches all of these to a GitHub Release at the same
version ([Releasing](docs/guides/releasing.md)). Nothing is pushed to other registries.

| Release asset | For |
| --- | --- |
| `kith-relay-<target>.tar.gz` / `.zip` | running the relay (Linux, macOS, Windows; x86_64 + arm64) |
| `kith-wasm-X.Y.Z.tgz` | web, Electron, Node (`npm install <asset URL>`) |
| `kith-swift-package.zip` + `KithFFI.xcframework.zip` | iOS, macOS |
| `kith-android-X.Y.Z.aar` | Android |
| `SHA256SUMS` | verifying downloads |

Rust apps depend on the crates through a git tag, and the relay image is
built from `apps/relay-server/Dockerfile`.

## Status

Current state, decisions and next steps: [PLAN.md](PLAN.md).

Alpha. **Web is the supported platform** (npm package, IndexedDB, browser tests in CI). The Swift and Kotlin
packages are released as **non-production** previews: they compile and are tested in CI, but their live-sync
glue has not been run on real devices, so don't ship them to users yet.

Working today: signed change history, SQLite / IndexedDB persistence, JSON documents that merge
(Automerge), live sync and catch-up through an authenticated relay, end-to-end encryption (one MLS
group per organization), invitations with membership certificates the relay checks, roles and write rules,
read-restricted subgroups, encrypted files, encrypted backups, and an always-on client.

Start with [Getting started](docs/guides/getting-started.md) and read the [threat model](docs/guides/threat-model.md) before real data goes in.

Known limits: history is kept in full until an admin sets a retention rule and compacts it (REQ-DATA-005), so
the whole history sits in memory on the web (plan for a few ten thousand changes per device); sync needs another member online (run the always-on client);
no independent security audit yet. See the
[traceability matrix](docs/requirements/TRACEABILITY.md) for per-requirement status.

## License

[MIT](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
