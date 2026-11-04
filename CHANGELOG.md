# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Fork resolution for concurrent MLS commits (ADR 0004): a competing commit for the epoch just
  passed is detected (`CommitOutcome::Fork`, `Event::Fork`); the commit from the lower device ID
  wins on every device and devices on the losing branch are re-added automatically. Commit
  catch-up now starts one epoch early and carries the committer of each commit; a member's
  undecryptable message for the current epoch triggers a commit request. MLS state format v2.

### Added
- End-to-end encryption on the wire (REQ-ENC-001..004): every relay body is an MLS message for
  the org's group. `Client::create_group`, `join_request_frame`, `add_member`, `remove_member`,
  `rotate_key`, `is_member`, `group_members`; new events `JoinRequested`, `Joined`, `GroupChanged`,
  `EpochBehind`, `CommitsServed`, `CommitsApplied`, `ReAddRequested`, `MemberReAdded`. Missed
  commits are fetched from a peer automatically, and a device beyond the commit log is re-added
  automatically. The MLS state is saved in the store (`Store::get_meta`/`put_meta`; SQLite schema 2,
  IndexedDB version 2) before anything encrypted is sent. Same API in `kith-net` (`LiveClient`),
  web (`createGroup`, `requestJoin`, `addMember`, ...), Swift/Kotlin (`KithClient.createGroup`,
  `RelaySession.joinRequest`/`addMember`/...; Swift `RelayConnection`).

### Changed
- **Breaking:** plaintext bodies are refused; clients must be in the org's group to send or read.
  `broadcast_frame` and `sync_request_frame` are now `Client` methods and return `Result`;
  `Client::new` returns `Result` (it loads the MLS state). `Store` has two new required methods.

### Added
- `kith-crypto`: MLS group encryption with OpenMLS (`Groups`, REQ-ENC-001..004, ADR 0004):
  ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, the device key signs MLS
  messages, KeyPackages, `create_group`, `add_member`/`readd_member`/`remove_member`, `join`,
  `encrypt`/`decrypt`, `apply_commit` with epoch-gap detection, `self_update`, a commit log
  (`commits_since`) and save/restore. Not wired into the client yet.

### Changed
- MSRV is now Rust 1.91 (required by `openmls` 0.9).

### Added
- Catch-up sync (REQ-SYNC-001..003): a returning or new device asks one online peer for what it
  lacks and offers what the peer lacks (`Client::sync_request_frame`; answers through
  `Client::handle_frame`, which now returns `Handled { event, replies }`). `LiveClient::catch_up` (Rust),
  `client.catchUp()` (web), `RelaySession.catchUp()` and `RelayConnection.catchUp()` (Swift/Kotlin).
  The ID comparison is still the naive full-set exchange (about 32,000 changes per device).

### Changed
- Relay frame bodies now start with a kind byte (`1` change, `2` have, `3` offer). Not compatible
  with 0.1.0-alpha.1 clients (alpha; the relay itself is unaffected, it never reads bodies).

### Added
- Swift/Kotlin: `KithClient.relaySession(org)` → `RelaySession` (`hello`, `receive`, `broadcast`) for live sync;
  the app owns the WebSocket. Swift: `RelayConnection` on `URLSessionWebSocketTask`. `kith_client::handshake_reply`
  is shared by the web and UniFFI bindings (REQ-SYNC-004).

### Added
- Web: `client.connect(url, org, onEvent)` / `disconnect()` for live sync over `WebSocket`; `create`/`edit`
  broadcast, peers' changes are validated and stored and reported to `onEvent` (REQ-SYNC-004).
  The smoke test runs it against the real relay.

### Added
- `kith-net` (native): `RelayConnection` (authenticated WebSocket) and `LiveClient`, which
  broadcasts each new change and validates received ones (REQ-SYNC-004). `kith-client`:
  `Client::handle_frame`, `Event`, `announce_frame`, `broadcast_frame`. Optional `tls` feature for `wss://`.
- `kith-relay-server` is also a library (`app`, `new_state`) so tests can run a relay in-process.

### Fixed
- Relay: connections are closed with a proper WebSocket close frame instead of being dropped.

### Added
- Relay: device authentication by challenge/response (REQ-RELAY-004, device-key half). Other frames are
  refused until a device authenticates; connections that don't authenticate within
  `KITH_RELAY_AUTH_TIMEOUT_SECS` (default 10) are closed. `kith_core::verify_signature`,
  `kith_protocol::auth_message`, `kith_client::{hello_frame, auth_frame}`.

### Fixed
- Relay: a device that reconnected was unregistered when its old connection closed; the old
  connection is now closed on reconnect and cannot remove the new one.

### Added
- `kith-merge`: `Merger` trait and Automerge implementation; `Client::materialize` merges an
  object's forked history deterministically (REQ-DATA-004, ADR 0003). Automerge is opt-in
  (`kith-client/automerge`).

### Changed
- MSRV is now Rust 1.90 (required by `automerge` 0.12).

### Added
- Web: `generateSecretKey()` and `await KithClient.open(dbName, secretKey)` persist changes in
  IndexedDB (write-through cache, REQ-STORE-001). `kith_store::codec` encodes changes as bytes.

### Added
- Swift/Kotlin: `generateSecretKey()` and `KithClient.open(dbPath, secretKey)` persist changes in
  SQLite (REQ-STORE-001). `Store` is implemented for `Box<dyn Store>`.

### Added
- Bindings: `secretKey()` and `KithClient.withSecretKey(...)` (Swift, Kotlin, JS) restore the
  device identity across restarts; `Client::signer()` in `kith-client`.

### Added
- `kith_store::SqliteStore` (feature `sqlite`, native only): persistent append-only
  change store with a rebuildable `objects` table (REQ-STORE-001).

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
