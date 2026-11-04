# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Relay abuse limits (REQ-RELAY-006): `Limits` (env `KITH_RELAY_DEVICE_FRAMES_PER_SEC`, `_DEVICE_BURST`,
  `_DEVICE_BYTES_PER_SEC`, `_ORG_FRAMES_PER_SEC`, `_MAX_CONNECTIONS`, `_MAX_MESSAGE_BYTES`,
  `_MAX_REFUSED`), `new_state_with`. Excess frames get `rate-limited` and are dropped; persistent
  abusers are disconnected; too many connections get HTTP 503.
- Clients keep at most `MAX_QUARANTINE` rejected changes per author.

### Added
- Encrypted files (REQ-FILE-001/002, ADR 0009): `kith_crypto::files` (XChaCha20-Poly1305 chunks of
  256 KiB, chunk ID = SHA-256 of the ciphertext), `Store::put_chunk` / `get_chunk` (SQLite table,
  IndexedDB version 3), `kith.file` objects. `Client::add_file(_in)`, `file_info`, `missing_chunks`,
  `read_file`, `fetch_file_frames`, `set_fetch_files`; events `ChunksServed`, `FileChunks`,
  `ChunksMissing`. Web `addFile`, `addFileIn`, `fileInfo`, `readFile`, `fetchFile`, `setFetchFiles`;
  FFI the same; the always-on client fetches eagerly.

### Added
- Always-on client (REQ-SYNC-006): `apps/always-on` (`kith-always-on --data DIR [--join LINK]`, crate
  `kith_always_on`): joins by invite, keeps key + SQLite in a data directory, stays connected with
  backoff, catches up periodically, rotates its group key weekly. Released as
  `kith-always-on-<target>` next to the relay binaries.
- `Membership.always_on` (protocol): the relay prefers certified always-on members as catch-up
  partners. `Client::set_always_on`; `LiveClient::into_client`.

### Added
- Read-restricted subgroups (REQ-PERM-003, ADR 0008): policy op `SetSubgroup`, one MLS group per
  subgroup run by its owner (members send it their KeyPackage automatically), data in scope
  `<org>/<name>` encrypted for and synced within the subgroup. `Client::create_subgroup`,
  `set_subgroup_members`, `subgroup_members`, `my_subgroups`, `sync_request_frames` (org +
  subgroups); `Event::MemberAdded`. Web `createSubgroup`, `setSubgroupMembers`, `subgroupMembers`,
  `mySubgroups`; FFI `RelaySession.createSubgroup` & co.

### Changed
- `RelaySession.catchUp` (FFI) returns several frames; MLS catch-up messages carry their group.

### Changed
- **Breaking:** every change is signed with its scope (`kith/change/v2`, ADR 0007): `local`, an org,
  or (later) a subgroup. Catch-up, offers, broadcasts and policy checks work per scope, so one store
  can hold several orgs. `Client::create` uses the default scope (the only org, else `local`);
  `create_in` / `create_document_in` (web `createIn`, FFI `createIn`) choose one. `Store::scope_ids`;
  codec v2 and SQLite schema 3 (older non-empty databases are refused).

### Added
- Write permissions (phase 6, ADR 0006): a `kith.policy` object per org (`kith_core::policy`:
  `PolicyOp`, `Policy::fold`, `Role`), created with the org. `Client::set_role`, `set_write_rule`,
  `revoke`, `role_of`, `policy`; every incoming change is checked (REQ-PERM-002), forbidden ones are
  quarantined (hidden from history, merge and edits, still forwarded), dependents of rejected changes
  are rejected, and stored changes are re-checked when the policy changes. Web `setRole`,
  `setWriteRule`, `roleOf`; Swift/Kotlin `RelaySession.setRole`, `setWriteRule`, `roleOf`.

### Changed
- `remove_member` and `grant_admin` return several frames: `remove_member` also revokes the device
  in the policy (REQ-INV-004), `grant_admin` also records the admin role.
- `ClientError::Forbidden` for writes the policy does not allow.

### Added
- Invitations (phase 5, ADR 0005): `Client::create_org` (org ID = new org root public key),
  `create_invite` (one-time, expiring link), `claim_invite` (proof + 6-digit code),
  `Event::InviteClaimed` → `accept_claim` / `reject_claim`, `grant_admin`; the Welcome carries the
  new member's certificate and the client re-announces with it (`Event::CertificateUpdated` for
  admin grants). Same API in `kith-net` (`claim`, `accept_claim`), web (`createOrg`, `createInvite`,
  `parseInvite`, `claimInvite`, `acceptClaim`, `rejectClaim`, `grantAdmin`), Swift/Kotlin. The web
  and Swift wrappers queue frames until the relay handshake is done.
- Relay: membership proofs are checked on `announce` (REQ-RELAY-004); devices without one are
  pending (only `invite-claim`, which goes to the org's online admins, and incoming `direct`);
  `not-a-member` and `bad-proof` errors. `kith_relay::Role`, `RoutingTable::join_as`, `admins`.

### Changed
- **Breaking:** `create_group`, `join_request_frame`, `add_member` and `Event::JoinRequested` are
  gone (join by invite). `handshake_reply` / `announce_frame(org)` are `Client` methods (they carry
  the certificate). Org IDs must be org root keys (64 hex).

### Added
- `kith_core::membership` (ADR 0005): membership certificates and chains (root → admin → member)
  that the relay can verify against the org ID (= org root public key), one-time invite links
  (`Invite::to_link` / `parse`), the claim proof (HMAC over the KeyPackage) and a 6-digit short
  code. Not wired into the relay and client yet.

### Changed
- Catch-up uses range-based set reconciliation (Negentropy, `kith_sync::Reconciliation` / `respond`)
  instead of exchanging all change IDs: no more ~32,000-change limit (`ClientError::SyncTooLarge` is
  gone), traffic grows with the difference. `Event::SyncServed` no longer has counts; the requester
  gets the new `Event::SyncCompared { sending, wanting }` (both 0: in sync). Offers split long want
  lists. Inner body kinds: `2` (have) replaced by `4` (query) / `5` (reply).

### Added
- JSON documents in all bindings (REQ-DATA-004): `createDocument`, `updateDocument` (RFC 7396 merge
  patch) and `documentJson` on web, Swift and Kotlin; `Client::create_document`, `update_document`,
  `document_json` in Rust (feature `automerge`, which the bindings enable). `kith_merge::automerge_merger`
  gains `to_json` and `merge_patch`. The web package grows to about 3.2 MB (`.wasm`, uncompressed).

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
