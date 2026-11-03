# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Repository structure: Rust workspace, relay server, UniFFI and WASM bindings, Swift and Android packaging.
- Signed, hash-linked change envelope (REQ-DATA-001..003), in-memory store, naive reconciliation, relay routing table.
- Requirements as code with traceability check; CI and release workflows.
- CI: fmt, clippy, tests on Linux/macOS/Windows, MSRV (1.88), per-crate wasm32 check,
  npm package build + Node smoke test, UniFFI binding generation, relay image smoke test.
- Release: relay image (amd64/arm64) and binaries, npm, Swift package, Android AAR,
  optional crates.io; manual dry run builds everything without publishing.
- Issue templates (requirement, bug), PR template, CODEOWNERS, Dependabot.

### Fixed
- Web: `create`/`edit` panicked in the browser because `SystemTime::now()` is
  unavailable on wasm32-unknown-unknown; the JS clock is used there.
- Web: `wasm-opt` rejected modules built with Rust >= 1.87 (bulk memory and other
  default wasm features).
- Library crates now build for wasm32 on their own (`getrandom` `js` feature moved
  into `kith-core`).
