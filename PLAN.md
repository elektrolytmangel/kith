# Plan and status

The single place to see where kith stands, what was decided, and what comes
next. **Read this first when you pick up work. Update it whenever you make a
plan or finish a piece of work** (see [CLAUDE.md](CLAUDE.md)).

- **Last updated:** 2026-11-05 (build and release hardening: pinned Actions/images, cargo deny, attestations, SBOM)
- **Version:** `v0.1.0-alpha.3` released (2026-11-05). `main` carries unreleased: relay revocation (#55), relay org
  allowlist (#57). Whether the two ghcr.io packages are public is the user's step (see *Publishing the images*).
- **State of `main` (16e991b, #57 merged):** CI green on all 12 jobs on #57. Locally checked: fmt, clippy (incl. wasm32),
  workspace tests, wasm32 per crate, MSRV 1.91, npm smoke test against the real relay.
- **Repository:** <https://github.com/elektrolytmangel/kith> (public, MIT)

## Where things stand

### Done

| Area | State |
| --- | --- |
| Repository structure | Rust workspace (`crates/`), relay server (`apps/relay-server`), always-on client (`apps/always-on`), bindings (UniFFI → Swift/Kotlin, wasm-bindgen → npm), docs, requirements, ADRs. See [README](README.md). |
| Requirements as code | 43 requirements in `docs/requirements/`, traced to tests by `scripts/reqs.py` ([TRACEABILITY.md](docs/requirements/TRACEABILITY.md)). |
| CI (`ci.yml`) | fmt, clippy, tests on Linux/macOS/Windows, MSRV 1.91, wasm32 per crate, npm build + Node smoke test, UniFFI generation, Swift package + `swift test`, Android AAR, relay image + `/healthz`, requirements check. |
| Release (`release.yml`) | Tag `vX.Y.Z` → GitHub Release with relay + always-on binaries, npm tarball, Swift package + XCFramework, Android AAR, `SHA256SUMS`. GitHub Releases is the only publish target. Dry run verified 2026-11-03 ([run](https://github.com/elektrolytmangel/kith/actions/runs/41680667767)): every package built. |
| Dependencies | Current as of 2026-11-04: ed25519-dalek 3, sha2 0.11, rusqlite 0.41, automerge 0.12, openmls 0.9, negentropy 0.5, chacha20poly1305 0.10, argon2 0.6, Gradle 9.8.2, AGP 9.5, JNA 5.19.1, Actions. No open Dependabot PRs. |
| Template | `scripts/rename.py --name <n> --owner <o>` rebrands everything; tested on a copy. |

### What the library can do today (alpha, phases 1-7 and 8a/8b done)

Requirements: 32 implemented, 8 partial, 3 accepted/proposed, 1 rejected.

Works, on Rust, web (npm), Swift and Kotlin unless noted:
- signed, hash-linked changes; per-object history and fork detection; device keys that can be saved and restored;
- persistence: SQLite (Rust, Swift, Kotlin: `KithClient.open`), IndexedDB (web: `KithClient.open`);
- relay with device authentication (challenge/response); live sync of new changes between online devices
  (`kith-net` in Rust, `KithClient.connect` on web, `RelaySession` on Swift/Kotlin);
- catch-up: a new or returning device downloads what it lacks from one online peer (`catchUp`);
- invitations: `createOrg`, one-time invite links with short codes, admins, relay-checked certificates;
- write permissions: roles (viewer/editor/admin), per-type write rules, revocation; enforced on every device;
- scopes (one store, several orgs) and read-restricted subgroups with their own encryption;
- encrypted files in verifiable chunks, fetched from any peer (falls back to the author); the always-on client `kith-always-on`;
- relay abuse limits (rate limits, size and connection caps); passphrase-encrypted backups with re-add on restore;
- end-to-end encryption (MLS, one group per org): admission by invite, remove, key rotation,
  automatic commit catch-up, re-add and fork resolution; the relay sees only routing metadata;
- merging concurrent edits: JSON documents on Automerge on every platform (`createDocument`, `updateDocument`,
  `documentJson`); pluggable `Merger` in Rust.

**Not usable for real apps yet:**

| Gap | Effect | Requirement |
| --- | --- | --- |
| A device added by the losing side of an MLS fork needs a new invite | Rare (two admins at once) | ADR 0004 |
| A device added as a member's own device cannot add devices itself; subgroups list devices, not users | Link from the original device; admin lists linked devices | ADR 0011 |
| Restoring a backup while the original device still runs makes them re-add each other | Restore only when the original is gone | ADR 0010 |
| A removed device is refused by the relay only while the relay remembers the signed notice. By default that is RAM: after a restart it can connect again until the issuing admin reconnects (opt-in persistence in Azure Table: ADR 0014). Other admins and the always-on client do not repeat notices yet | Turn on persistence; share notices with other admins | ADR 0013, 0014 |
| Subgroup membership changes need the subgroup's owner device online; ownership cannot move | ADR 0008 | REQ-PERM-003 |
| Sync needs another member online | Run the always-on client (`kith-always-on`) | REQ-SYNC-006 |
| Swift/Kotlin live-sync glue is only compiled in CI, never run against a relay | Unverified on devices | REQ-SYNC-004 |

Fine for: building and testing an integration, and trials with users who accept alpha risk. No security review
yet, and formats may still break between alphas.

## Plan

Phases follow the [design doc](docs/design/0001-local-first-e2ee-sync.md#technology-stack-and-implementation-phases).
Work top to bottom; check items off here as they land.

### Next steps (in order)

1. [x] Release `v0.1.0-alpha.2` (#42 merged and tagged by the user).
2. [x] **REQ-ID-002, users with several devices** (option A decided 2026-11-04: the member signs its own device's
   certificate; ADR 0011, PR `feat/own-devices`): `LinkDevice` policy op, own-device certificates (chains of up to 3),
   `create_own_device_invite` (web/FFI), `InviteClaim.to` routing, removal covers linked devices.
3. **Road to a release users can use:** see the next section (agreed with the user 2026-11-04). Next open item: step 3
   there (real-device verification), then 4. The freeze point is decided (first beta), so step 2 can be finished: migrations and previous-protocol support at the freeze.
4. **Unplanned:** push wake-ups (REQ-RELAY-007, only for apps in the background), moving subgroup ownership; mark the repository as a
   template (owner only).

### Road to a release users can use (user agreed 2026-11-04; work in this order after step 0)

0. [x] **CI skips docs-only changes** (`paths-ignore` in `ci.yml`: Markdown, `docs/**`, LICENSE, templates; #47).
   A docs-only PR therefore has no checks (merge it directly), except requirement edits. Requirements-only changes run only
   `requirements.yml` (`scripts/reqs.py`).

Blockers, in suggested order:

1. [ ] **Security review** of the crypto and protocol (MLS use, certificates, policy, backups, relay). Nothing is
   claimed safe for real data until this is done.
2. [~] **Compatibility promise** (ADR 0012 accepted, golden tests for the change envelope and store codec in #50): versioned wire/storage formats with migrations (alpha.1 data already breaks on
   `main`), a stated semver policy, and the first non-alpha version number.
3. [ ] **Run on real devices:** Swift/Kotlin live-sync glue against a relay (REQ-SYNC-004), the `partial` platform
   requirements (REQ-PLAT-002..005, REQ-RELAY-001).
4. [~] **Closing known gaps:** [x] relay-level certificate revocation (REQ-INV-004, ADR 0013, PR `feat/relay-revocation`; notice sharing between admins open), always-on client as the supported
   way to sync offline devices (push wake-ups REQ-RELAY-007 later), resumable large syncs (REQ-SYNC-005),
   history compaction (REQ-DATA-005; the web store keeps all history in memory). Push wake-ups are unplanned.
5. [x] **Containers for the relay and the always-on client** (#48; dry run of `release.yml` verified, both images built and smoke-tested) (replaces "publish packages"; user decision
   2026-11-04: nothing is published outside GitHub). Plan: `release.yml` builds a multi-arch image per binary from
   the release binaries (no Rust compile in the image) and pushes it to GitHub Packages (ghcr.io) with
   `GITHUB_TOKEN`; plus a `docker-compose.yml` example and a deployment guide. Chosen over "Dockerfile that
   downloads the release" because users then just `docker run`/`pull`.
6. [ ] **Docs for adopters:** per-platform getting started, a small example app, relay deployment guide (TLS,
   limits, always-on client), threat model and the known limits above.

### Web readiness (PR `feat/web-readiness`; user asked for all of it on 2026-11-04)

1. [x] **Several tabs of one app:** `KithClient.open` takes an exclusive Web Lock per database (REQ-PLAT-006); a second
   tab gets an error, or `open(db, key, true)` waits. Without `navigator.locks` (Node < 24, very old browsers) there is
   no guard (documented).
2. [x] **Tests in a real browser:** `bindings/wasm/tests/browser/run.mjs` (Playwright 1.62.1, Chromium) in the CI `wasm`
   job: strict CSP, reload persistence, tab lock, key storage, two browsers through the relay incl. a relay restart.
   Only Chromium; Firefox and WebKit are not tested.
3. [x] **Connection handling:** automatic reconnect with backoff, `online` event, `connected` / `reconnecting` events
   (REQ-PLAT-007). The relay does not check `Origin` (documented; auth is by device key). Offline writes are stored and
   exchanged by `catchUp` after a reconnect (not automatic).
4. [x] **Key and storage safety:** `kith-web.js` (`loadOrCreateDeviceKey`, `requestPersistentStorage`,
   `storageEstimate`; REQ-PLAT-008). Not testable here: Safari's 7-day eviction.
5. [x] **Size and memory measured** (`KITH_MEASURE=10000,50000`): wasm 3.4 MiB (1.3 gzip); 50k changes: open 5.9 s,
   38 MiB. Compaction (REQ-DATA-005) is still open; the docs state the limit.
6. [x] **Adopter material:** `examples/web-vite` (built in CI), `docs/guides/web-production.md`, CSP note (REQ-PLAT-009).
7. [x] **Found on the way:** no binding could list objects. Added `objects(type?)` in Rust, web and FFI (REQ-DATA-007).

Not done / open for the web: Firefox and WebKit tests; `SharedWorker` pattern for several usable tabs (documented only);
automatic `catchUp` after reconnect; the Swift/Kotlin `objects()` call is compiled in CI but not run on devices.

### Completed phases (reference)

Details are in the ADRs, the Log and `git log`. PRs: #28-#30 MLS, #31 documents, #32 Negentropy, #33-#34
invitations, #35-#37 policy, scopes, subgroups, #38-#39 always-on client and files, #40 abuse limits, #41 backups.

1. **Phase 4, Encryption (MLS / OpenMLS)**: REQ-ENC-001..004. **Required before any real user data.**
   Design decided ([ADR 0004](docs/adr/0004-mls-openmls-rustcrypto.md)).
   - [x] 4a `kith_crypto::Groups` (OpenMLS, KeyPackages, add/re-add/remove, commit log, save/restore), MSRV 1.91 (PR `feat/mls-group`).
   - [x] 4b+4c Client + bindings: every body MLS-encrypted, auto commit catch-up, auto re-add, MLS state in
     `Store` meta (saved before sending); web/Swift/Kotlin/`kith-net` group API; smoke test joins through the relay
     (PR `feat/mls-client`). wasm package 1.97 MB with OpenMLS.
   - [x] 4d Concurrent-commit forks (PR `feat/mls-forks`): every device remembers its last epoch transition
     (committer + commit hash; for a Welcome: the adder). A different commit for that epoch = fork. Winner = lower
     committer device ID (then lower hash). Loser sends one KeyPackage to the peer on the winning branch, which
     re-adds it (existing re-add path). Commit requests are served from one epoch earlier so the requester can spot a
     fork; a member's undecryptable message at our own epoch triggers a commit request. Limit: a device that the
     losing commit added must be admitted again (app sees `JoinRequested`). Periodic `rotate_key` stays app-driven.
2. [x] **Merged state in the bindings** (REQ-DATA-004): JSON documents (`createDocument`, `updateDocument` with RFC 7396
   merge patches, `documentJson`) on all platforms (PR `feat/documents`). wasm: 1.97 MB → 3.18 MB with Automerge.
3. **Phase 3 follow-ups**: [x] range-based reconciliation (Negentropy in `kith-sync`, PR `feat/negentropy`);
   offline peers: decided, no relay buffer; the always-on client (phase 7) covers it.
4. **Phase 5, invitations** (decisions in *Decisions*; ADR 0005):
   - [x] 5a `kith-core::membership`: org root key per org (org ID = its public key), membership certificates
     (root → admin, admin → member; chain of ≤ 2), invite links (org, relay, token, secret, expiry), claim proof
     (HMAC over the KeyPackage) and 6-digit short code. Pure library + tests (PR `feat/membership`).
   - [x] 5b Relay: verify certificate chains on `announce` (REQ-RELAY-004); devices without one are *pending*
     (may only send `invite-claim` and receive `direct`); claims go to the org's online admins.
   - [x] 5c Client + bindings (5b+5c in PR `feat/invitations`): `create_org`, `create_invite`, `claim_frame`, `InviteClaimed { code }` →
     `accept_claim`, Welcome carries the member certificate, re-announce with it; `grant_admin`; remove
     `create_group` / open `JoinRequested` admission; e2e through the relay; smoke test.
5. **Phase 6, permissions** (decisions in *Decisions*; ADR 0006):
   - [x] 6a Policy object (PR `feat/policy`; invalid changes are quarantined, not dropped, see ADR 0006) (`kith.policy`, ID derived from the org): ops `Genesis` (creator's root-signed admin cert),
     `SetRole` (admin needs a root-signed cert), `SetRule` (min write role per object type), `Restrict` (revoke or
     demote, with a keep list of the device's change IDs the admin had seen). Deterministic fold: causal order,
     concurrent ops by seniority (root, then admin order) then change ID; an op counts only if its author is an
     admin at that point. Every incoming change validated (REQ-PERM-002); invalid parents make children invalid;
     policy tightening re-checks stored changes and hides invalid ones from history, merge and sync.
     `remove_member` also revokes. Bindings: `setRole`, `setWriteRule`, `roleOf`; events `PolicyChanged`.
   - [x] 6b-1 Scope in the change envelope (ADR 0007) (`kith/change/v2`): `Scope` = org, `org/name` or `local` (never synced);
     codec v2, SQLite schema 3 (refuses older non-empty databases), `Store::scope_ids`; sync, live delivery and
     policy checks per scope; `create` uses the default scope (the only org, else `local`), `create_in(scope, …)`
     for several orgs. Lifts the "one org per store" limit (PR `feat/scope`).
   - [x] 6b-2 Subgroups (REQ-PERM-003, PR `feat/subgroups`, ADR 0008): policy op `SetSubgroup { name, members, keep }` (admins);
     the creating device is the subgroup's MLS owner (group key `org/name`) and is the only one that adds/removes in
     MLS (no forks); members listed in the policy send it a KeyPackage. A decrypted message's MLS group is its scope,
     so catch-up/offers run per subgroup with no new fields; MLS catch-up messages get a group field. Writes in
     `org/S` need membership of S + role. Limit: membership changes wait for the owner device to be online.
6. **Phase 7, always-on client and files** (order decided by the user):
   - [x] 7a Always-on client (PR `feat/always-on`): `Membership.always_on` (certified members only; the relay
     prefers them as sync partners), `apps/always-on` binary `kith-always-on` (join by invite link, data dir with
     key + SQLite, reconnect with backoff, periodic catch-up, weekly key rotation = REQ-ENC-003), release asset.
   - [x] 7b Encrypted large files (REQ-FILE-001/002, PR `feat/files`, ADR 0009): random key per file, XChaCha20-
     Poly1305 chunks of 256 KiB, chunk ID = SHA-256 of the ciphertext; `kith.file` object (name, MIME, size, key,
     chunk IDs) in the normal change flow; chunks in the store tagged with their scope (`Store::put_chunk`); fetch via
     an encrypted `ChunkWant` (org: sync-request routing, so the always-on client is preferred; subgroup: direct),
     answered with verified `Chunks`; peers serve only chunks of their scope. Lazy by default (`fetch_file`),
     eager on request (`set_fetch_files`); the always-on client fetches eagerly.
7. **Phase 8, hardening** (user's order):
   - [x] 8a Relay abuse limits (REQ-RELAY-006, PR `feat/abuse-limits`): WebSocket message/frame caps; token buckets per
     device (frames/s, bytes/s) and per org (frames/s) via env vars; excess → `rate-limited` error and drop, far
     over → disconnect; max connections; client caps quarantined invalid changes per author.
   - [x] 8b Encrypted backups (PR `feat/backups`, ADR 0010): `export_backup(passphrase)` = device key, changes, chunks, org
     state (certs, root key), **not** the MLS state (restoring old ratchets would reuse encryption keys);
     Argon2id + XChaCha20-Poly1305. `import_backup` restores into a new store; on the next presence the device
     asks an online member to re-add it (existing re-add path). Only when the original device is gone.
   - [x] Release PR `v0.1.0-alpha.2` (#42, version bump + changelog); **the user merges and tags**.
   - Later: compaction (REQ-DATA-005), push wake-ups (REQ-RELAY-007), security review.
### Open questions for the user

- **Azure plan:** all six steps done. Never deployed to real Azure (managed identity path, Bicep): the first deploy is the test.
  Step 2 used the defaults: allowlist in an Azure Table (live reload every 30 s), Table over Blob.

### Plan: approved orgs, durable relay state, Azure Container Apps + Bicep

Facts: the relay serves any org unless `KITH_RELAY_ALLOWED_ORGS` is set (step 1). Online connections, auth challenges and rate
buckets are per-process and cannot move to storage. Durable candidates: the **allowlist** (approved org IDs = root
public keys) and the **revocation notices** (ADR 0013). Functions are not an option (no WebSocket server); Container
Apps runs the relay with min = max = 1 replica (it is one in-memory router).

1. [x] **Org allowlist** in the relay (REQ-RELAY-008, #57 merged): refuse `announce` for orgs not on the list (error
   `org-not-allowed`, also for pending devices); empty/unset = open (today's behaviour, for local use). Source:
   `KITH_RELAY_ALLOWED_ORGS` (env) first; read at start, applies to later announces (step 2 makes it live).
   Open edge: removing an org from the list does not disconnect its devices already announced (they leave on
   reconnect); step 2 should evict them on reload.
2. [x] **`StateStore` trait in the relay** (PR `feat/relay-state-store`): `kith_relay_server::state::{StateStore, StaticState,
   spawn_allowlist_refresh}`; Azure Table implementation `state::azure::AzureTables` over plain REST behind cargo feature
   `azure-state` (reqwest/rustls; auth: managed identity via `IDENTITY_ENDPOINT`, or connection string = SharedKeyLite).
   Table `allowedorgs` (PartitionKey `org`, RowKey org ID); re-read every 30 s; an empty or missing table approves nobody,
   a failed read keeps the last list (startup failure exits). Removing an org evicts its online devices
   (`set_allowed_orgs`, also closes the step 1 edge). Linux release binaries and the Dockerfile build with the feature.
   CI job `relay azure state` runs the integration test against Azurite (`tests/azure.rs`, incl. paging).
   Not yet tried against real Azure (managed identity path is untested; step 4/6 deployment will exercise it).
   The `revocations` table is not built (step 3).
3. [x] **Revocation notices persisted, optional** (PR `feat/persist-revocations`, ADR 0014; user asked 2026-11-05 for an opt-in): `KITH_RELAY_PERSIST_REVOCATIONS=true` + Azure Table `revocations`; verified again on load; off by default so ADR 0013's RAM-only stays the default. Bicep `persistRevocations`.
4. [x] **Bicep** in `deploy/azure/` (PR `feat/azure-bicep`; lint + build verified locally with `az bicep`, never deployed; custom domain / managed certificate left out of the template because DNS validation must precede the binding: do it in the guide with `az containerapp hostname add/bind`) (`main.bicep` + `main.bicepparam` example): Log Analytics, Container Apps
   environment, the app (image `ghcr.io/elektrolytmangel/kith-relay:<version>`, port 8080, external ingress, min=max=1,
   env limits), Storage account (Table), **user-assigned managed identity** with role *Storage Table Data Contributor*
   (no storage keys in the app), managed certificate + custom domain optional, optional ingress IP restrictions. All
   names and the domain are parameters (the template repo is rebranded by `scripts/rename.py`).
5. [x] **CI** (`.github/workflows/bicep.yml`): `az bicep build` / `bicep lint` job on changes under `deploy/azure/` (path-filtered); a `what-if` stays a
   manual step in the guide (needs credentials).
6. [x] **Docs** (PR `docs/deployment-azure`; the whole template and the managed identity path have never run against real Azure, say so when the user deploys): `docs/guides/deployment-azure.md` (prerequisites, `az deployment group create`, approving an org,
   making the ghcr.io package public or adding registry credentials, costs); link from `deployment.md`.

Where Bicep lives: **in this repo** (`deploy/azure/`), next to `deploy/docker-compose.yml`. It is a generic, reusable
module and versions with the relay (image tag, env vars, new settings). Environment-specific parameter files
(subscription, domain, secrets) belong in a private repo or the operator's pipeline, not here.

### Open issues

- **macOS jobs get cancelled or wait long** (diagnosed 2026-11-03 from job annotations). Causes:
  1. GitHub macOS arm64 capacity: "The job was not acquired by Runner … even after multiple attempts"
     (PR #3, PR #10). Not our code; *Re-run failed jobs*.
  2. CI concurrency cancelled `main` runs on every merge. Fixed: `cancel-in-progress` only for PRs.
  3. Manual cancellations from the UI (release dry run, one `main` run).
  If capacity problems persist: merge the `test (macos-latest)` and `Swift package` jobs into one
  macOS job (the Swift build already compiles the Rust crates for macOS), halving macOS runner demand.

## Decisions (don't re-litigate without the user)

| Decision | Why | Where |
| --- | --- | --- |
| Revocation persistence is an opt-in relay feature (`KITH_RELAY_PERSIST_REVOCATIONS`, Azure Table); default stays RAM-only | User request (2026-11-05) | ADR 0014 |
| Relay revocation: admin-signed notices, held in RAM only, repeated by the issuing admin on announce (not short-lived certificates, no on-disk list) | User choice (2026-11-05) | ADR 0013 |
| Format freeze point = the first beta (`0.2.0-beta.1`, after the security review and device verification): from then on a release reads the previous release's data and speaks the previous protocol. Alphas may keep breaking | User decision (2026-11-04) | ADR 0012 |
| Push wake-ups (REQ-RELAY-007) stay unplanned: only background apps need them | User decision (2026-11-04) | Road to a release |
| CI does not run for docs-only changes (Markdown, `docs/**`, PLAN, requirements); such PRs have no checks and are merged directly. requirement edits run only `requirements.yml` | User request (2026-11-04) | `ci.yml` |
| Distribution: nothing outside GitHub (no npm/Maven/crates.io). Relay and always-on client ship as containers on GitHub Packages (ghcr.io), built from the release binaries | User decision (2026-11-04), replaces the package-registry idea | Road to a release, step 5 |
| Users with several devices (REQ-ID-002): any member may admit its own extra device (same user, same role, never admin this way); admitting others stays admin-only. The member itself signs the device's relay certificate (option A) | User choice (2026-11-04) | ADR 0011 |
| Phase 8 scope: relay abuse limits first, then encrypted backups; compaction and push wake-ups later | User choice (2026-11-04) | Phase 8 |
| Prepare a `v0.1.0-alpha.2` release PR (version bump + changelog); **the user merges and tags** | User choice (2026-11-04) | PR #42 |
| Every signed change names its scope (org or org/subgroup); sync, encryption, permissions per scope | User choice (2026-11-04); also lifts "one org per store" | Phase 6b |
| Subgroups are managed by org admins through policy ops; one MLS group per subgroup | User choice (2026-11-04) | Phase 6b |
| After 6b: phase 7 (always-on client, then files) before phase 8 hardening | User choice (2026-11-04) | Plan order |
| Permissions: one signed `kith.policy` object per org, admin-written, validated like any object | User choice (2026-11-04) | Phase 6, REQ-PERM-001 |
| Fixed roles admin / editor / viewer; per object type a minimum write role | User choice (2026-11-04) | Phase 6 |
| Revocation wins: a restricted device's changes count only if the admin had seen them (keep list); dependents of rejected changes are rejected | User choice (2026-11-04) | Phase 6, REQ-PERM-004 |
| Read-restricted subgroups (REQ-PERM-003) come after write permissions | User choice (2026-11-04) | Phase 6b |
| Org ID = root public key (hex); members carry a root-signed membership certificate the relay checks statelessly | User choice (2026-11-04) | Phase 5, REQ-RELAY-004 |
| Only admins invite/admit (root + devices the root certifies as admin); members may still re-add themselves | User choice (2026-11-04), until phase 6 roles | Phase 5 |
| Invites: single-use, expiring (e.g. 24 h), claim proves the secret; 6-digit short code optional (app decides) | User choice (2026-11-04) | Phase 5 |
| No relay buffer for offline devices; reliability comes from the always-on client (phase 7) | User choice (2026-11-04); keeps "stores nothing" | REQ-RELAY-005 |
| MLS ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, OpenMLS + RustCrypto provider | User choice (2026-11-04): reuses Ed25519 device key, pure Rust, builds on wasm32 | Phase 4 ADR 0004 |
| KeyPackages travel `direct` to an online admin; relay stays stateless | User choice (2026-11-04) | Phase 4 / 5 |
| Until phase 5: creator makes the group (first admin), low-level `add_member(key_package)` → commit + Welcome | User choice (2026-11-04); invitations wrap it later | Phase 4 |
| Encryption is a hard break: plaintext bodies rejected, no migration; keep going through the plan after MLS | User choice (2026-11-04), alpha | Phase 4 |
| Mobile bindings are sans-IO: the app owns the WebSocket, Rust owns the protocol (`RelaySession`) | Keeps tokio/TLS out of iOS/Android builds, uses platform networking | `bindings/ffi/src/lib.rs` |
| Name `kith`, owner `elektrolytmangel` | User's choice; repo renamed to `kith` | `rename.py` replaces both |
| License MIT, copyright Marc Muehlheim | User's choice | `LICENSE`. `authors` in Cargo.toml stays "kith contributors" (user said no) |
| Publish to GitHub Releases only | User: "not more is needed". No npm/Maven/ghcr/crates.io pushes | `release.yml`, [releasing.md](docs/guides/releasing.md) |
| First release is the pre-release `v0.1.0-alpha.1` | The library is a phase 1 skeleton; the version should say so | Next steps 1 |
| Phase 1 starts with SQLite store + key restore in the bindings | Minimum for an app to keep data and device identity across restarts | Next steps 3 |
| Agent merges its own PRs when all CI checks pass; tags/releases stay the user's | User: "when the CI passes, you merge by yourself" (2026-11-04) | `CLAUDE.md`, Working agreements |
| Web persistence = write-through cache over IndexedDB (not an async `Store`) | `Store` is sync; keeps one trait for all platforms. Cost: whole history in memory | `bindings/wasm/src/idb.rs` |
| After each successful merge, continue with the next plan item without asking | User: "Continue automatically after each merge completed successful" (2026-11-04) | `CLAUDE.md` |
| Merging: Automerge by default, pluggable `Merger` per type; MSRV raised to 1.90 for automerge 0.12 | User chose "Automerge default + pluggable per-type merger" (2026-11-04); MSRV bump is mine (0.7.x needed a fragile `hexane` lockfile pin) | [ADR 0003](docs/adr/0003-merge-automerge-default-pluggable.md) |
| Rust core, thin bindings | Same validation/merge logic everywhere | [ADR 0001](docs/adr/0001-monorepo-rust-core-thin-bindings.md) |
| Requirements as code | Versioned with code, traced to tests | [ADR 0002](docs/adr/0002-requirements-as-code.md) |
| Randomness only via `kith_core::random_bytes()` (getrandom); no `rand_core` | ed25519-dalek majors change rand_core; seed → `SigningKey::from_bytes` | `crates/kith-core/src/lib.rs`; RFC 8032 test vector guards signatures |
| AGP 9 built-in Kotlin, no Kotlin Android plugin | AGP 9 rejects the separate plugin | `bindings/kotlin/*.gradle.kts` |
| Dependabot groups AGP + Gradle wrapper | They only work together | `.github/dependabot.yml` |
| Swift and Android built in CI | Repo is public (free macOS); Android PRs passed untested before | `ci.yml` |

## Pitfalls already hit

- **Green Dependabot PR ≠ working.** Before the Android CI job existed, Gradle/AGP PRs passed without any Android build. Check which jobs actually cover the change.
- **UniFFI metadata is stripped** from release cdylibs (`strip = true`). Generate bindings from an unstripped host build (`scripts/build-android.sh` does).
- **wasm32:** `std::time::SystemTime::now()` panics (use `js_sys::Date`); `wasm-opt` needs the feature flags in `bindings/wasm/Cargo.toml` for Rust ≥ 1.87.
- **Signatures must stay byte-identical** across crypto upgrades: keep `rfc8032_test_vector_1` passing.
- **Local machine has no Rust toolchain.** Run everything in Docker (`rust:1-bookworm`), see [Run CI locally](docs/guides/development.md#run-ci-locally). Android: `cimg/android:2026.10.1`.

- **`git push` over SSH fails intermittently** too. Fallback: `git -c credential.helper='!gh auth git-credential' push https://github.com/elektrolytmangel/kith.git <branch>`, then `gh pr create --head <branch>`.
- **`git pull` over SSH can fail** ("Permission denied (publickey)"). The repo is public: `git fetch https://github.com/elektrolytmangel/kith.git main && git merge --ff-only FETCH_HEAD`. Then check `git log`, otherwise you test a stale `main`.
- **Cargo.lock matters:** CI uses `--locked`. After changing dependencies run `cargo metadata` (or `cargo update -p ...`) in Docker and commit the lockfile.
- **automerge** 0.7.x does not compile against current `hexane`; 0.12 needs Rust 1.90. **openmls 0.9 needs 1.91** (current MSRV). Don't downgrade.
- **Web tests locally:** build the wasm package and relay in `rust:1-bookworm` (`cargo install wasm-pack --locked` into a cached volume), then run `bindings/wasm/tests/smoke.mjs` in the official `node:22` image with `KITH_RELAY_BIN` set (Node 18 from apt can't load the ES module). The apt `binaryen` is too old for `wasm-opt`; CI uses wasm-pack's own.
- **Don't pipe downloaded installers into `sh`**: the permission classifier blocks it. Use apt, `cargo install --locked` or official images.
- **OpenMLS on wasm32** needs `openmls/js` (getrandom 0.4 `wasm_js` + web-time); set per target in `kith-crypto/Cargo.toml`.
- **OpenMLS refuses a Welcome for an existing group** (`GroupAlreadyExists`): `Groups::join` uses `build_from_welcome(..).replace_old_group()`.
- **Wire formats:** relay bodies are `[outer kind][MLS message]` (0x10-0x18), with inner kinds 1 and 3-8. Changes are
  signed with `kith/change/v2` (the scope is included). SQLite schema 3 and IndexedDB v3 refuse older data.
  alpha.1 clients and databases don't work with `main`.
- **GitHub API flakes** (502s, missed `pull_request` events, "merge already in progress"): retry the merge via REST
  (`gh api -X PUT repos/.../pulls/N/merge -f merge_method=merge`, poll `.merged`), and delete the branch with
  `gh api -X DELETE repos/.../git/refs/heads/<branch>`. If a PR shows no checks, close and reopen it.
- **Stacked PRs:** after the lower PR merges, rebase the next branch onto `main` before pushing. Tests appended at
  the end of `crates/kith-client/src/tests.rs` conflict, and resolving the conflict can drop a closing brace.
- **Timing-sensitive tests:** the rate-limit tests accept small ranges. Smoke-test `waitFor` predicates must match
  the specific object, because events from earlier steps are still in the list.
- **The relay routes `direct` messages to a device's current connection**, so late answers from a previous session
  can arrive after a reconnect. Wait for the state you need, not for the first matching event.
- **Argon2 cost:** crates that depend on `kith-client` build it without `cfg(test)`, so their tests use the real
  64 MiB cost (about 6 s in debug).

## Working agreements

- Branch from `main`, open a PR, wait for CI (docs-only PRs have none, merge directly). **Once every check is green the agent merges its own PR**
  (`gh pr merge --merge --delete-branch`; decided 2026-11-04). Never merge on red or pending checks, never
  force-push. Tags and releases stay the user's.
- `gh` is logged in as `finocchio-42` (push access, not admin).
- Commits end with the `Co-Authored-By` line; PR descriptions follow `.github/pull_request_template.md`.

## Log

- **2026-11-03**: Structure, CI, release pipeline (PR #1). License, Gradle wrapper, owner URLs, Swift CI.
  Dependabot review: merged #3, #7; replaced #2/#4/#5/#6/#8 with #9 (ed25519-dalek 3 + sha2 0.11) and
  #10 (Gradle 9 + AGP 9 + Android CI, fixed stripped-metadata bug). Release dry run: all packages build.
  This plan written; user accepted the recommendations (alpha pre-release, phase 1 starts with store + key restore).
  macOS cancellations diagnosed; CI no longer cancels runs on `main`.
- **2026-11-04**: Opened the `0.1.0-alpha.1` version-bump PR (Next steps 1). Next: user merges and tags.
- **2026-11-04**: PR #13 merged. User set up branch protection on `main`.
- **2026-11-04**: Added `SqliteStore` (PR `feat/sqlite-store`). Next: key restore in bindings, then store selection in constructors.
- **2026-11-04**: `v0.1.0-alpha.1` released; label, vulnerability reporting set up; #15 merged. Added key restore to bindings (PR `feat/key-restore`). Next: store selection (SQLite path) in binding constructors.
- **2026-11-04**: Swift/Kotlin can persist (`KithClient.open`, PR `feat/ffi-sqlite`). Cross-compiling bundled SQLite for iOS/Android is only verified by CI. Next: IndexedDB store for web, then REQ-DATA-004 (Automerge).
- **2026-11-04**: Rule change (user): agent merges its own PRs once CI is green. CLAUDE.md and Working agreements updated.
- **2026-11-04**: Web IndexedDB persistence (PR `feat/web-indexeddb`); smoke test runs it against `fake-indexeddb` (verified locally in `node:22`). User rule: continue with the next plan item after every successful merge. Next: REQ-DATA-004 (Automerge).
- **2026-11-04**: `kith-merge` + `Client::materialize` (PR `feat/merge-automerge`); MSRV 1.90. Next: Phase 2 (WebSocket transport, relay device auth) or merge bindings.
- **2026-11-04**: Relay device authentication + reconnect fix (PR `feat/relay-device-auth`). Next: WebSocket `Transport` client, live updates.
- **2026-11-04**: `kith-net` + `Client::handle_frame` live sync (PR `feat/live-sync`); relay now a lib + bin and sends a close frame. Next: browser WebSocket client, then bindings.
- **2026-11-04**: Web live sync (`KithClient.connect`, PR `feat/web-live-sync`), smoke-tested against the real relay. Next: Swift/Kotlin connect, then phase 3 catch-up.
- **2026-11-04**: Swift/Kotlin live sync via sans-IO `RelaySession` + Swift `RelayConnection` (PR `feat/ffi-live-sync`). Next: phase 3 catch-up sync (REQ-SYNC-001..003).
- **2026-11-04**: Catch-up sync (PR `feat/catch-up-sync`): `sync_request_frame` + offers, `Handled` replies, all bindings; e2e test through the relay. Next: phase 4 (MLS) needs a design discussion (OpenMLS, key packages, ADR).
- **2026-11-04 (summary of the day)**: `v0.1.0-alpha.1` released (#13) and repository settings done by the user.
  Phase 1: SQLite store (#15), key restore (#16), `KithClient.open` on Swift/Kotlin (#17), IndexedDB store (#19),
  `kith-merge` + ADR 0003 (#21, MSRV 1.90). Phase 2: relay device auth (#22), `kith-net` live sync (#23), web live sync (#24),
  Swift/Kotlin `RelaySession` (#25). Phase 3: catch-up sync (#26). Rule changes by the user: the agent merges its own
  PRs when CI is green (#18), continues after each merge. Dependabot #20 (rusqlite 0.41) tested against `main`, merged by the user.
  **Stopped on the user's request** after re-checking `main`; next is Phase 4 (needs a design decision).
- **2026-11-04**: User answered the phase 4 questions (see *Decisions*). `kith_crypto::Groups` on OpenMLS + ADR 0004, MSRV 1.91 (PR `feat/mls-group`). Next: 4b client integration.
- **2026-11-04**: #28 merged. Client + bindings on MLS (PR `feat/mls-client`): encrypted bodies, join flow, commit catch-up, re-add, `Store` meta. Smoke test (web, real relay) passes locally. Next: 4d or REQ-DATA-004 bindings.
- **2026-11-04**: MLS fork resolution (PR `feat/mls-forks`): lower committer ID wins, losers re-added; tests cover both orders and a device that missed the winning commit. Next: REQ-DATA-004 merged state in bindings.
- **2026-11-04**: JSON documents in all bindings (PR `feat/documents`), wasm 3.18 MB. Next: phase 3 follow-ups (Negentropy).
- **2026-11-04**: Negentropy reconciliation replaces the full-ID exchange (PR `feat/negentropy`); new `SyncCompared` event. Next: phase 5 invitations (design questions first).
- **2026-11-04**: User decided phase 5 questions (see *Decisions*). 5a `kith_core::membership` + ADR 0005 (PR `feat/membership`). Next: 5b relay checks.
- **2026-11-04**: Invitations end to end (PR `feat/invitations`): relay checks certificate chains, pending devices, claim/accept flow in all bindings; smoke test joins by invite. Next: phase 6 permissions (design questions).
- **2026-11-04**: User decided phase 6 questions. Policy object, roles, rules, revocation with keep lists, quarantine (PR `feat/policy`, ADR 0006). Next: 6b read-restricted subgroups, or phase 7.
- **2026-11-04**: User decided 6b questions (scope in envelope, admins manage subgroups, then phase 7). 6b-1 scopes (PR `feat/scope`, ADR 0007). Next: 6b-2 subgroups.
- **2026-11-04**: #36 merged. Subgroups (PR `feat/subgroups`, ADR 0008); smoke test covers them. Next: phase 7 (always-on client, then files).
- **2026-11-04**: #37 merged. Always-on client `kith-always-on` + `Membership.always_on` (PR `feat/always-on`), e2e test through the relay. Next: 7b files.
- **2026-11-04**: #38 merged. Encrypted files (PR `feat/files`, ADR 0009); smoke test fetches a file through the relay. Next: phase 8 hardening (needs priorities from the user).
- **2026-11-04**: User set phase 8 order (abuse limits, then backups) and asked for an alpha.2 release PR. Relay abuse limits + quarantine cap (PR `feat/abuse-limits`). Next: release PR, then 8b backups.
- **2026-11-04**: Encrypted backups (PR `feat/backups`, ADR 0010); the always-on client exports/restores. Next: alpha.2 release PR.
- **2026-11-04**: #39-#41 merged (files, with an author fallback added after a CI flake; abuse limits; backups).
  Release PR #42 opened for the user. The user decided REQ-ID-002 (members admit their own devices). **Stopped
  on the user's request**; PLAN updated (PR `docs/plan-state`). Next: user merges #42 and tags alpha.2, then
  REQ-ID-002 (open question first).
- **2026-11-04**: PR #42 conflicts resolved (merged `main` into the release branch). User chose option A for REQ-ID-002.
  Implemented own devices (PR `feat/own-devices`, ADR 0011). Next: merge when CI is green; then the small items.
- **2026-11-04**: #44 merged (REQ-ID-002, all 11 checks green). The user merged #42 and tagged `v0.1.0-alpha.2`.
  PLAN updated. Next: small items or a deferred item, user's choice.
- **2026-11-04**: User asked what a proper release needs; proposal written under *Road to a release users can use*.
- **2026-11-04**: User agreed the road to a release and replaced the package-registry step by containers on ghcr.io.
  First: CI skips docs-only changes (PR `ci/skip-docs-only`). Next: step 1 onwards (containers, then the rest).
- **2026-11-04**: #47 merged (docs-only CI filter). Container images (PR `feat/containers`): `docker/Dockerfile`, `containers` job in
  `release.yml` (ghcr.io, amd64+arm64, no `latest` for pre-releases), `deploy/docker-compose.yml`, deployment guide.
  After the first release with images, the user makes the packages public once. Next: step 1 (compatibility policy), then 3.
- **2026-11-04**: #48 merged (container images; dry run verified). Format guards: golden tests for the change envelope and the store codec, ADR 0012 (proposed). Next: user picks the freeze point; then step 3 (devices) and 4 (gaps).
- **2026-11-04**: User decided: freeze point = first beta; push wake-ups unplanned. Web readiness list added (multi-tab safety first).
- **2026-11-04**: Web readiness (PR `feat/web-readiness`): tab lock, reconnect, `kith-web.js`, `objects()`, browser tests in CI, Vite example, web production guide.
  Next: step 3 (Swift/Kotlin on devices; needs a macOS/Android runner or device), step 4 (gaps), step 6 docs for other platforms.
- **2026-11-05**: Release PR `release/0.1.0-alpha.3` (version bump, changelog, doc links). Release dry run on the branch before merge.
- **2026-11-05**: Road step 4, first gap: relay-level revocation (PR `feat/relay-revocation`, ADR 0013). User chose RAM-only signed notices. Next: share notices with other admins / always-on, then resumable syncs (REQ-SYNC-005), compaction (REQ-DATA-005).
- **2026-11-05**: User asked where to host the relay and how to limit it to approved orgs (no allowlist yet). User wants Azure Container Apps with Table/Blob state and Bicep; plan written (allowlist, StateStore, Bicep in `deploy/azure/`), awaiting go-ahead.
- **2026-11-05**: Azure plan step 1 done: relay org allowlist `KITH_RELAY_ALLOWED_ORGS` (REQ-RELAY-008, #57). #56 merged. Plan refreshed; next: step 2 (`StateStore`, Azure Table).
- **2026-11-05**: Azure plan step 2: `StateStore`, Azure Table allowlist with live reload and eviction, Azurite CI job (PR `feat/relay-state-store`). Next: step 4 (Bicep); step 3 waits for the user's OK on amending ADR 0013.
- **2026-11-05**: #59 merged (StateStore). Bicep template + lint CI (PR `feat/azure-bicep`). Next: step 6 (Azure guide); step 3 waits for the user's OK.
- **2026-11-05**: #60 merged (Bicep + lint CI). Azure guide `docs/guides/deployment-azure.md`. Next: user deploys and confirms ADR 0013 amendment (step 3); otherwise road step 4 gaps (REQ-SYNC-005) or step 1 security review prep.
- **2026-11-05**: #61 merged. User asked for step 3 as an opt-in: revocation persistence (ADR 0014, PR `feat/persist-revocations`). Azure plan complete. Next: road step 4 gaps (REQ-SYNC-005), security review prep, or the user's first real Azure deploy.
- **2026-11-05**: CI on `main` red since the relay-limits merge (wasm browser test every run, kith-net join test intermittently): both tests raced the relay registering an announce (now checked off the lock). Tests now wait for presence, like the others (PR `test/wait-for-relay-membership`). No product change; integration guide notes when live changes start reaching a new device.
- **2026-11-05**: Build and release hardening (PR `chore/supply-chain`): Actions pinned to SHAs, base images to digests, `cargo deny` workflow (`deny.toml`, weekly + on dependency changes; three build-time/unused-curve advisories ignored with reasons), Dependabot covers all npm/Docker/Compose dirs, release SBOM + build provenance attestations, Azure role scoped to the two tables (old account-wide assignment must be deleted by hand on existing deployments).
