# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-11-04

First pre-release: a phase 1 skeleton (in-memory store, no encryption). Not for real user data.

### Added
- Repository structure: Rust workspace, relay server, UniFFI and WASM bindings, Swift and Android packaging.
- Signed, hash-linked change envelope (REQ-DATA-001..003), in-memory store, naive reconciliation, relay routing table.
- Requirements as code with traceability check; CI and release workflows.
- CI: fmt, clippy, tests on Linux/macOS/Windows, MSRV (1.88), per-crate wasm32 check,
  npm package build + Node smoke test, UniFFI binding generation, Swift package build +
  `swift test` on macOS, Android AAR build (Gradle 9.8.2, AGP 9.5), relay image smoke test.
- Release: GitHub Release with relay binaries, npm tarball, Swift package, Android AAR
  and SHA256SUMS; manual dry run builds everything without creating a release.
- Issue templates (requirement, bug), PR template, CODEOWNERS, Dependabot.
- MIT license.
- Gradle wrapper (8.11.1, distribution checksum pinned) for the Android package.

### Changed
- Rust: ed25519-dalek 3, sha2 0.11; keys and IDs come from `kith_core::random_bytes()`
  (getrandom), rand_core is no longer a dependency.

### Fixed
- Web: `create`/`edit` panicked in the browser because `SystemTime::now()` is
  unavailable on wasm32-unknown-unknown; the JS clock is used there.
- Web: `wasm-opt` rejected modules built with Rust >= 1.87 (bulk memory and other
  default wasm features).
- Library crates now build for wasm32 on their own (`getrandom` `js` feature moved
  into `kith-core`).
