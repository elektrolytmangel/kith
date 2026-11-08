# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Compatibility machinery for the freeze** ([ADR 0012](docs/adr/0012-format-stability.md)): SQLite schema migration
  steps (none needed yet), a relay that accepts a range of protocol versions (`MIN_PROTOCOL_VERSION`), and fixture tests
  (SQLite database, backup file) that every later release must keep passing. No format changed.
- **Automatic catch-up after a (re)connect** (web, REQ-PLAT-007): once a `presence` event shows another device online,
  the client runs one `catchUp` by itself. Calling `catchUp()` yourself still works; no format or protocol change.

## [0.1.0-alpha.6] - 2026-11-06

History compaction. **Compatible with 0.1.0-alpha.5**; see *Upgrading*.

### Added
- **History compaction** (REQ-DATA-005, [ADR 0026](docs/adr/0026-history-compaction.md)): an admin sets a
  retention rule per object type (`setRetention`: `all` by default, `last:N`, `days:N`) and folds old
  history into signed snapshots (`compact`). Devices delete the folded changes and keep only their IDs.
  Raw objects keep their newest changes, documents keep their content, old file versions lose their chunks
  (new `updateFile`). Stores gain `delete` and `delete_chunk`; no format or protocol version changes.

### Upgrading
- Nothing to migrate: stored formats and the wire protocol are unchanged, and alpha.5 and alpha.6 devices and relays work
  together. Compaction is off until an admin sets a retention rule.
- Upgrade **every device** before an admin sets a rule: older clients do not know snapshots, show their bytes as
  an ordinary change and never delete anything.
- Custom `Store` implementations must add `delete` and `delete_chunk`.

## [0.1.0-alpha.5] - 2026-11-06

Notice sharing, batched sync rounds and adopter docs. **Compatible with 0.1.0-alpha.4** (same stored
formats and wire protocol); see *Upgrading*.

### Upgrading
- Nothing to migrate: stored formats and the wire protocol are unchanged. Alpha.4 and alpha.5 devices and
  relays work together, with one catch: an alpha.4 device catching up from an alpha.5 device gets one batch
  (500 changes) per catch-up, because it ignores the `More` message. Upgrade all devices together, or call
  `catchUp` again until nothing new arrives. Alpha.4 devices show the two new messages as `Rejected` events.
- Removals made before alpha.5 are held only by the admin who issued them; removals from now on are
  also held by the other admins and the always-on client.

### Added
- Large catch-ups run in rounds of at most 500 changes / 2 MiB and continue where they stopped after an
  interruption ([ADR 0025](docs/adr/0025-batched-sync-rounds.md)). Old clients ignore the new `More` message (see *Upgrading*).
- Revocation notices are shared with the other admins and the always-on client, so any of them can
  restore a restarted relay's list ([ADR 0024](docs/adr/0024-shared-revocation-notices.md)). Old clients
  show the new message as `Rejected` and keep working.

### Documentation
- New [Getting started](docs/guides/getting-started.md) and [Threat model and known limits](docs/guides/threat-model.md).
- The web package is the supported platform; the Swift and Kotlin packages are non-production previews
  (live sync never ran on real devices). History is never compacted yet (REQ-DATA-005, planned): see
  the README and the guides for the limit.

## [0.1.0-alpha.4] - 2026-11-06

Review fixes, relay revocation and allowlist, build and release hardening. **Not compatible with
0.1.0-alpha.3:** see *Upgrading*.

### Upgrading
- **Stored data:** stores from earlier alphas can't be opened (the org and MLS state is now
  encrypted, [ADR 0021](docs/adr/0021-sealed-stored-secrets.md)). Export a backup with alpha.3 and
  restore it with alpha.4, or invite the device again.
- **All devices and the relay change together:** invites between alpha.3 and alpha.4 devices fail
  (new short-code exchange, [ADR 0023](docs/adr/0023-claim-nonce-sync-peer-native-tls.md)), and claims
  travel in a new relay frame (`claim-deliver`, [ADR 0018](docs/adr/0018-relay-revocation-rules.md)).
- **Existing orgs:** the device holding the org root key must start alpha.4 once, so the policy gets
  its root-signed genesis ([ADR 0015](docs/adr/0015-policy-genesis-and-named-members.md)).
- **Invite API:** `claimInvite` (web), `RelaySession.claim` (Swift/Kotlin), `claim_invite` and
  `LiveClient::claim` (Rust) no longer return the short code. It arrives as an event once the admin
  answers: `claimCode` (web), `RelayEvent.ClaimCode` / `.claimCode`, `Event::ClaimCode`.
  `RelaySession.claim` returns the frame bytes (no `ClaimOutput`).
- **Native client (`kith-net`, always-on client):** `wss://` works out of the box (TLS is a default
  feature); plain `ws://` is accepted only for a relay on the same machine.
- **Azure:** after redeploying, delete the relay identity's old account-wide role assignment
  ([deployment-azure.md](docs/guides/deployment-azure.md#updating-cost-limits)).
- **Always-on client:** `--join -` reads the invite link from stdin (a link on the command line
  still works, with a warning); `KITH_BACKUP_PASSPHRASE_FILE` is preferred over
  `KITH_BACKUP_PASSPHRASE`.

### Security
Fixes from the 2026-11 review (internal and external) of the client, policy, relay and native
network code ([ADRs 0015-0023](docs/adr/README.md)). All earlier versions are affected; upgrade
every device and the relay.
- Critical: a client accepted an unsolicited MLS Welcome and replaced the org's encryption group
  ([GHSA-w42p-rf3h-qqxx](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-w42p-rf3h-qqxx), ADR 0016).
- Critical: a rival policy genesis from a root-certified admin took over the org policy
  ([GHSA-xr6v-qq86-27m3](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-xr6v-qq86-27m3), ADR 0015).
- High: uncertified authors counted as editors; linking, un-revoking and backdating bypassed roles
  ([GHSA-phpw-5h6c-rvcm](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-phpw-5h6c-rvcm), ADR 0015).
- High: MLS commits were not authorized by policy role; a re-add changed state before the sender
  was checked ([GHSA-2w6q-fch9-2q26](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-2w6q-fch9-2q26), ADR 0017).
- High: revoked admins could still revoke others at the relay; pending announces bypassed
  revocation ([GHSA-32v8-6gqm-8v8x](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-32v8-6gqm-8v8x), ADR 0018).
- High: relay resource exhaustion (unbounded queues and state, no idle timeout, verification under
  the global lock) ([GHSA-c5jv-3fvw-5672](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-c5jv-3fvw-5672), ADR 0019).
- High: unbounded recursion and no size cap when materializing Automerge documents
  ([GHSA-r2g8-h8ph-gfgm](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-r2g8-h8ph-gfgm), ADR 0020).
- Medium: secrets stored or exposed in plaintext (org root key, MLS state, always-on key and logs)
  ([GHSA-36qv-j64f-c6rj](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-36qv-j64f-c6rj), ADR 0021).
- Low: client and relay hardening: invites reusable at admission, certificate downgrade, error
  echo, non-strict signatures; also the invite short code, catch-up peer, commit resend and native
  TLS ([GHSA-mrg7-v28j-wqgw](https://github.com/elektrolytmangel/kith/security/advisories/GHSA-mrg7-v28j-wqgw), ADRs 0022, 0023).

### Added
- Relay-level revocation (REQ-INV-004, [ADR 0013](docs/adr/0013-relay-revocation.md)): `remove_member` signs a
  revocation notice that the relay verifies from the org ID, keeps in RAM and uses to drop the device (and its own
  devices) and refuse it on `announce`. `Membership.revoked` in the protocol is optional, so older clients still work.
- Relay: `KITH_RELAY_ALLOWED_ORGS` restricts a relay to approved organizations (REQ-RELAY-008); other orgs get
  `org-not-allowed` on `announce`. Unset keeps today's behaviour (every org).
- Relay: approved orgs can come from an Azure Table (`KITH_RELAY_AZURE_STORAGE_ACCOUNT` with a managed identity, or
  `KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING`; cargo feature `azure-state`, included in the Linux container images).
  The list is re-read every 30 s (`KITH_RELAY_ALLOWLIST_REFRESH_SECS`), so approving an org needs no restart, and
  devices of an org removed from the list (also from `KITH_RELAY_ALLOWED_ORGS`) are dropped from it. An empty table
  approves nobody. New `StateStore` trait in `kith_relay_server::state`.
- Relay: optional persistence of revocation notices (`KITH_RELAY_PERSIST_REVOCATIONS=true`, Azure Table `revocations`,
  [ADR 0014](docs/adr/0014-optional-revocation-persistence.md)); notices are verified again on load, so a restart no
  longer lets a removed device back in. Off by default (the relay then stores nothing, as before). Bicep parameter
  `persistRevocations`.

### Changed
- Build and release: GitHub Actions pinned to commit SHAs, base images (Dockerfiles, Compose) pinned to digests,
  `cargo deny` checks advisories, licenses and sources (`deny.toml`, on dependency changes and weekly), Dependabot
  covers the Docker and Compose files and the npm test packages. Releases carry an SPDX SBOM and signed build provenance for every
  file and image (`gh attestation verify`, see [releasing.md](docs/guides/releasing.md#verifying-a-release)).
- Azure template: the relay's identity gets *Storage Table Data Contributor* on its tables only, not on the storage
  account. Existing deployments keep the old account-wide assignment until it is deleted
  ([deployment-azure.md](docs/guides/deployment-azure.md#updating-cost-limits)).
- Policy: the root key signs the policy's genesis; a device has a role only if the policy names it; a
  restriction only lowers a role and wins over the restricted admin's concurrent policy changes
  ([ADR 0015](docs/adr/0015-policy-genesis-and-named-members.md)).
- Groups: a device accepts only Welcomes it asked for, and only admins (and subgroup owners) change a
  group's members ([ADR 0016](docs/adr/0016-welcome-checks.md), [ADR 0017](docs/adr/0017-commit-authorization.md)).
- Relay: removing an admin needs a notice signed by the org root key; invite claims have their own frame
  ([ADR 0018](docs/adr/0018-relay-revocation-rules.md)). New limits: per-connection outbox, write and
  idle timeouts, connections per client address, a separate budget for pending devices
  (`KITH_RELAY_MAX_QUEUED_BYTES`, `KITH_RELAY_WRITE_TIMEOUT_SECS`, `KITH_RELAY_IDLE_TIMEOUT_SECS`,
  `KITH_RELAY_MAX_CONNECTIONS_PER_IP`, `KITH_RELAY_CLIENT_IP_HEADER`, `KITH_RELAY_PENDING_FRAMES_PER_SEC`;
  [ADR 0019](docs/adr/0019-relay-resource-limits.md)).
- Documents: received Automerge changes are checked before they are applied; documents are limited to
  100 levels ([ADR 0020](docs/adr/0020-checked-automerge-changes.md)).
- Storage: the org and MLS state is encrypted with a key derived from the device key; SQLite files and
  the always-on data directory are readable by the owner only ([ADR 0021](docs/adr/0021-sealed-stored-secrets.md)).
- Invites: checked again when the admin accepts (one device per invite, not after expiry); at most 8
  claims wait per invite; the short code includes a value the admin signs after the claim
  ([ADR 0022](docs/adr/0022-admission-and-secret-hygiene.md), [ADR 0023](docs/adr/0023-claim-nonce-sync-peer-native-tls.md)).
- Signatures are checked strictly (`verify_strict`); secrets are wiped from memory when dropped.
- Native client: TLS on by default (rustls with ring), `ws://` only to this machine, 16 MiB message
  limit ([ADR 0023](docs/adr/0023-claim-nonce-sync-peer-native-tls.md)).

### Fixed
- The always-on client release builds had no TLS support and could not connect to `wss://` relays.

## [0.1.0-alpha.3] - 2026-11-05

Web readiness, container images and format guards. Compatible with 0.1.0-alpha.2 (no format changes;
the golden tests pin them). `KithClient.open` and `KithClient.restoreBackup` take an optional last
argument `waitForLock`.

### Added
- Web: one owner per IndexedDB database (exclusive Web Lock; `KithClient.open(db, key, waitForLock?)`,
  REQ-PLAT-006), automatic relay reconnect with `connected` / `reconnecting` events (REQ-PLAT-007),
  `kith-web.js` helpers for an encrypted device key, persistent storage and the storage quota
  (REQ-PLAT-008), real-browser tests under a strict CSP (REQ-PLAT-009), example app `examples/web-vite`,
  guide [Web apps in production](docs/guides/web-production.md).
- `objects(type?)` in every binding: list the objects a device knows (REQ-DATA-007).
- Golden tests that pin the change envelope and the stored encoding, and [ADR 0012](docs/adr/0012-format-stability.md) (format versions and compatibility rules; frozen from the first beta).
- Container images for the relay and the always-on client on GitHub Packages (ghcr.io), built from the
  release binaries by `release.yml` (amd64, arm64); `deploy/docker-compose.yml` (relay with TLS) and
  [deployment guide](docs/guides/deployment.md).
- A member adds its own devices (REQ-ID-002, ADR 0011): `create_own_device_invite` (web
  `createOwnDeviceInvite`, FFI `createOwnDeviceInvite`), policy op `LinkDevice`, own-device
  membership certificates (chains of up to 3), `InviteClaim.to` so the relay routes the claim to the
  issuing member. The linked device has the member's role (at most editor); `remove_member` and
  revocation cover it.

## [0.1.0-alpha.2] - 2026-11-04

End-to-end encryption (MLS), invitations with relay-checked membership, write permissions and
read-restricted subgroups, JSON documents, encrypted files, range-based catch-up, the always-on
client, relay abuse limits and encrypted backups. Not compatible with 0.1.0-alpha.1 (wire format,
change envelope and stores changed).

### Added
- Encrypted backups (REQ-DATA-006, ADR 0010): `Client::export_backup(passphrase)` /
  `Client::import_backup(bytes, passphrase, store)` (Argon2id + XChaCha20-Poly1305; device key,
  changes, file chunks, org state; no MLS state: a restored device asks an online member to re-add
  it). Web `exportBackup`, `KithClient.restoreBackup`; FFI `exportBackup`, `KithClient.restore`;
  always-on `--export-backup` / `--restore-backup`.
- Relay abuse limits (REQ-RELAY-006): `Limits` (env `KITH_RELAY_DEVICE_FRAMES_PER_SEC`, `_DEVICE_BURST`,
  `_DEVICE_BYTES_PER_SEC`, `_ORG_FRAMES_PER_SEC`, `_MAX_CONNECTIONS`, `_MAX_MESSAGE_BYTES`,
  `_MAX_REFUSED`), `new_state_with`. Excess frames get `rate-limited` and are dropped; persistent
  abusers are disconnected; too many connections get HTTP 503.
- Clients keep at most `MAX_QUARANTINE` rejected changes per author.
- Encrypted files (REQ-FILE-001/002, ADR 0009): `kith_crypto::files` (XChaCha20-Poly1305 chunks of
  256 KiB, chunk ID = SHA-256 of the ciphertext), `Store::put_chunk` / `get_chunk` (SQLite table,
  IndexedDB version 3), `kith.file` objects. `Client::add_file(_in)`, `file_info`, `missing_chunks`,
  `read_file`, `fetch_file_frames`, `set_fetch_files`; events `ChunksServed`, `FileChunks`,
  `ChunksMissing`. Web `addFile`, `addFileIn`, `fileInfo`, `readFile`, `fetchFile`, `setFetchFiles`;
  FFI the same; the always-on client fetches eagerly.
- Always-on client (REQ-SYNC-006): `apps/always-on` (`kith-always-on --data DIR [--join LINK]`, crate
  `kith_always_on`): joins by invite, keeps key + SQLite in a data directory, stays connected with
  backoff, catches up periodically, rotates its group key weekly. Released as
  `kith-always-on-<target>` next to the relay binaries.
- `Membership.always_on` (protocol): the relay prefers certified always-on members as catch-up
  partners. `Client::set_always_on`; `LiveClient::into_client`.
- Read-restricted subgroups (REQ-PERM-003, ADR 0008): policy op `SetSubgroup`, one MLS group per
  subgroup run by its owner (members send it their KeyPackage automatically), data in scope
  `<org>/<name>` encrypted for and synced within the subgroup. `Client::create_subgroup`,
  `set_subgroup_members`, `subgroup_members`, `my_subgroups`, `sync_request_frames` (org +
  subgroups); `Event::MemberAdded`. Web `createSubgroup`, `setSubgroupMembers`, `subgroupMembers`,
  `mySubgroups`; FFI `RelaySession.createSubgroup` & co.
- Write permissions (phase 6, ADR 0006): a `kith.policy` object per org (`kith_core::policy`:
  `PolicyOp`, `Policy::fold`, `Role`), created with the org. `Client::set_role`, `set_write_rule`,
  `revoke`, `role_of`, `policy`; every incoming change is checked (REQ-PERM-002), forbidden ones are
  quarantined (hidden from history, merge and edits, still forwarded), dependents of rejected changes
  are rejected, and stored changes are re-checked when the policy changes. Web `setRole`,
  `setWriteRule`, `roleOf`; Swift/Kotlin `RelaySession.setRole`, `setWriteRule`, `roleOf`.
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
- `kith_core::membership` (ADR 0005): membership certificates and chains (root → admin → member)
  that the relay can verify against the org ID (= org root public key), one-time invite links
  (`Invite::to_link` / `parse`), the claim proof (HMAC over the KeyPackage) and a 6-digit short
  code. Not wired into the relay and client yet.
- JSON documents in all bindings (REQ-DATA-004): `createDocument`, `updateDocument` (RFC 7396 merge
  patch) and `documentJson` on web, Swift and Kotlin; `Client::create_document`, `update_document`,
  `document_json` in Rust (feature `automerge`, which the bindings enable). `kith_merge::automerge_merger`
  gains `to_json` and `merge_patch`. The web package grows to about 3.2 MB (`.wasm`, uncompressed).
- Fork resolution for concurrent MLS commits (ADR 0004): a competing commit for the epoch just
  passed is detected (`CommitOutcome::Fork`, `Event::Fork`); the commit from the lower device ID
  wins on every device and devices on the losing branch are re-added automatically. Commit
  catch-up now starts one epoch early and carries the committer of each commit; a member's
  undecryptable message for the current epoch triggers a commit request. MLS state format v2.
- End-to-end encryption on the wire (REQ-ENC-001..004): every relay body is an MLS message for
  the org's group. `Client::create_group`, `join_request_frame`, `add_member`, `remove_member`,
  `rotate_key`, `is_member`, `group_members`; new events `JoinRequested`, `Joined`, `GroupChanged`,
  `EpochBehind`, `CommitsServed`, `CommitsApplied`, `ReAddRequested`, `MemberReAdded`. Missed
  commits are fetched from a peer automatically, and a device beyond the commit log is re-added
  automatically. The MLS state is saved in the store (`Store::get_meta`/`put_meta`; SQLite schema 2,
  IndexedDB version 2) before anything encrypted is sent. Same API in `kith-net` (`LiveClient`),
  web (`createGroup`, `requestJoin`, `addMember`, ...), Swift/Kotlin (`KithClient.createGroup`,
  `RelaySession.joinRequest`/`addMember`/...; Swift `RelayConnection`).
- `kith-crypto`: MLS group encryption with OpenMLS (`Groups`, REQ-ENC-001..004, ADR 0004):
  ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, the device key signs MLS
  messages, KeyPackages, `create_group`, `add_member`/`readd_member`/`remove_member`, `join`,
  `encrypt`/`decrypt`, `apply_commit` with epoch-gap detection, `self_update`, a commit log
  (`commits_since`) and save/restore. Not wired into the client yet.
- Catch-up sync (REQ-SYNC-001..003): a returning or new device asks one online peer for what it
  lacks and offers what the peer lacks (`Client::sync_request_frame`; answers through
  `Client::handle_frame`, which now returns `Handled { event, replies }`). `LiveClient::catch_up` (Rust),
  `client.catchUp()` (web), `RelaySession.catchUp()` and `RelayConnection.catchUp()` (Swift/Kotlin).
  The ID comparison is still the naive full-set exchange (about 32,000 changes per device).
- Swift/Kotlin: `KithClient.relaySession(org)` → `RelaySession` (`hello`, `receive`, `broadcast`) for live sync;
  the app owns the WebSocket. Swift: `RelayConnection` on `URLSessionWebSocketTask`. `kith_client::handshake_reply`
  is shared by the web and UniFFI bindings (REQ-SYNC-004).
- Web: `client.connect(url, org, onEvent)` / `disconnect()` for live sync over `WebSocket`; `create`/`edit`
  broadcast, peers' changes are validated and stored and reported to `onEvent` (REQ-SYNC-004).
  The smoke test runs it against the real relay.
- `kith-net` (native): `RelayConnection` (authenticated WebSocket) and `LiveClient`, which
  broadcasts each new change and validates received ones (REQ-SYNC-004). `kith-client`:
  `Client::handle_frame`, `Event`, `announce_frame`, `broadcast_frame`. Optional `tls` feature for `wss://`.
- `kith-relay-server` is also a library (`app`, `new_state`) so tests can run a relay in-process.
- Relay: device authentication by challenge/response (REQ-RELAY-004, device-key half). Other frames are
  refused until a device authenticates; connections that don't authenticate within
  `KITH_RELAY_AUTH_TIMEOUT_SECS` (default 10) are closed. `kith_core::verify_signature`,
  `kith_protocol::auth_message`, `kith_client::{hello_frame, auth_frame}`.
- `kith-merge`: `Merger` trait and Automerge implementation; `Client::materialize` merges an
  object's forked history deterministically (REQ-DATA-004, ADR 0003). Automerge is opt-in
  (`kith-client/automerge`).
- Web: `generateSecretKey()` and `await KithClient.open(dbName, secretKey)` persist changes in
  IndexedDB (write-through cache, REQ-STORE-001). `kith_store::codec` encodes changes as bytes.
- Swift/Kotlin: `generateSecretKey()` and `KithClient.open(dbPath, secretKey)` persist changes in
  SQLite (REQ-STORE-001). `Store` is implemented for `Box<dyn Store>`.
- Bindings: `secretKey()` and `KithClient.withSecretKey(...)` (Swift, Kotlin, JS) restore the
  device identity across restarts; `Client::signer()` in `kith-client`.
- `kith_store::SqliteStore` (feature `sqlite`, native only): persistent append-only
  change store with a rebuildable `objects` table (REQ-STORE-001).

### Changed
- `RelaySession.catchUp` (FFI) returns several frames; MLS catch-up messages carry their group.
- **Breaking:** every change is signed with its scope (`kith/change/v2`, ADR 0007): `local`, an org,
  or a subgroup. Catch-up, offers, broadcasts and policy checks work per scope, so one store
  can hold several orgs. `Client::create` uses the default scope (the only org, else `local`);
  `create_in` / `create_document_in` (web `createIn`, FFI `createIn`) choose one. `Store::scope_ids`;
  codec v2 and SQLite schema 3 (older non-empty databases are refused).
- `remove_member` and `grant_admin` return several frames: `remove_member` also revokes the device
  in the policy (REQ-INV-004), `grant_admin` also records the admin role.
- `ClientError::Forbidden` for writes the policy does not allow.
- **Breaking:** `create_group`, `join_request_frame`, `add_member` and `Event::JoinRequested` are
  gone (join by invite). `handshake_reply` / `announce_frame(org)` are `Client` methods (they carry
  the certificate). Org IDs must be org root keys (64 hex).
- Catch-up uses range-based set reconciliation (Negentropy, `kith_sync::Reconciliation` / `respond`)
  instead of exchanging all change IDs: no more ~32,000-change limit (`ClientError::SyncTooLarge` is
  gone), traffic grows with the difference. `Event::SyncServed` no longer has counts; the requester
  gets the new `Event::SyncCompared { sending, wanting }` (both 0: in sync). Offers split long want
  lists. Inner body kinds: `2` (have) replaced by `4` (query) / `5` (reply).
- **Breaking:** plaintext bodies are refused; clients must be in the org's group to send or read.
  `broadcast_frame` and `sync_request_frame` are now `Client` methods and return `Result`;
  `Client::new` returns `Result` (it loads the MLS state). `Store` has two new required methods.
- MSRV is now Rust 1.91 (required by `openmls` 0.9).
- Relay frame bodies are MLS messages behind an outer kind byte (ADR 0004). Not compatible with
  0.1.0-alpha.1 clients.

### Fixed
- Relay: connections are closed with a proper WebSocket close frame instead of being dropped.
- Relay: a device that reconnected was unregistered when its old connection closed; the old
  connection is now closed on reconnect and cannot remove the new one.

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
