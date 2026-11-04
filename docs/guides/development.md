# Development

## Prerequisites

| For | Needs |
| --- | --- |
| Everything | Rust stable (pinned by `rust-toolchain.toml`), Python 3.11+ |
| Web package | `wasm-pack` |
| Swift package | macOS + Xcode |
| Android package | JDK 17, Android SDK + NDK, `cargo install cargo-ndk` (Gradle comes from `bindings/kotlin/gradlew`) |
| Relay image | Docker |

## Daily loop

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
python3 scripts/reqs.py --write     # after touching requirements or `req:` tags
```

## Where code goes

| Change | Crate |
| --- | --- |
| New field in the change envelope | `kith-core` (+ ADR, it breaks signatures) |
| New wire message | `kith-protocol` (+ bump `PROTOCOL_VERSION` if incompatible) |
| Storage | `kith-store` |
| Merging concurrent edits | `kith-merge` (`Merger` impls; Automerge is the default) |
| Sync algorithm | `kith-sync` (keep it sans-IO: no sockets, no clocks) |
| App-facing API | `kith-client`, then expose it in `bindings/ffi` and `bindings/wasm` |
| Relay behaviour | `kith-relay` (logic), `apps/relay-server` (I/O only) |

All library crates (everything under `crates/` except `kith-relay`) must
compile for `wasm32-unknown-unknown` on their own. CI checks this per crate.
Browser randomness comes from `getrandom` with the `js` feature, enabled in
`kith-core` so every crate above it inherits it.

## Platform builds

```sh
scripts/build-wasm.sh web            # → bindings/wasm/pkg
scripts/build-swift.sh               # → bindings/swift/KithFFI.xcframework (macOS only)
scripts/build-android.sh             # → bindings/kotlin/kith/src/main/{jniLibs,kotlin}
(cd bindings/kotlin && ./gradlew assembleRelease)
docker build -f apps/relay-server/Dockerfile -t kith-relay .
```

Update Gradle with `./gradlew wrapper --gradle-version <x.y.z>` in
`bindings/kotlin` (Dependabot also proposes updates).

Generated binding sources are not committed (see `.gitignore`). Hand-written
conveniences go in `bindings/swift/Sources/Kith/Extensions.swift` and
`bindings/kotlin/.../Extensions.kt`.

## Run CI locally

Every CI job (`.github/workflows/ci.yml`) is a plain command. Without a local
Rust install, run them in the official image:

```sh
docker run --rm -v "$PWD":/src:ro -w /src -e CARGO_TARGET_DIR=/tmp/t rust:1-bookworm bash -c '
  cargo fmt --all --check &&
  cargo clippy --workspace --all-targets --locked -- -D warnings &&
  cargo test --workspace --locked &&
  for c in kith-core kith-protocol kith-sync kith-crypto kith-store kith-merge kith-client; do
    cargo check --locked --target wasm32-unknown-unknown -p $c || exit 1; done &&
  rustup toolchain install 1.90 --profile minimal && RUSTUP_TOOLCHAIN=1.90 cargo check --workspace --locked'
python3 scripts/reqs.py
scripts/build-wasm.sh web && node bindings/wasm/tests/smoke.mjs   # needs wasm-pack + Node
docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:1.7.7   # after editing workflows
```

The Swift package needs macOS: run `scripts/build-swift.sh && (cd bindings/swift && swift test)`
on a Mac, or rely on the `swift` CI job. The `android` CI job builds the AAR.
To build every release package without creating a release, run the Release
workflow manually with `dry_run`.
