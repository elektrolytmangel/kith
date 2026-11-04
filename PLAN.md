# Plan and status

The single place to see where kith stands, what was decided, and what comes
next. **Read this first when you pick up work. Update it whenever you make a
plan or finish a piece of work** (see [CLAUDE.md](CLAUDE.md)).

- **Last updated:** 2026-11-04 (phase 4 in progress)
- **Version:** `v0.1.0-alpha.1` released as a pre-release. `main` has moved on (see Log) and is **not released**; the next tag is the user's call.
- **State of `main` (51e0b8b):** CI green on all 11 jobs; also re-checked locally after the rusqlite 0.41 bump (fmt, clippy, tests, wasm32 per crate, MSRV 1.90).
- **Repository:** <https://github.com/elektrolytmangel/kith> (public, MIT)

## Where things stand

### Done

| Area | State |
| --- | --- |
| Repository structure | Rust workspace (`crates/`), relay server (`apps/relay-server`), bindings (UniFFI → Swift/Kotlin, wasm-bindgen → npm), docs, requirements, ADRs. See [README](README.md). |
| Requirements as code | 41 requirements in `docs/requirements/`, traced to tests by `scripts/reqs.py` ([TRACEABILITY.md](docs/requirements/TRACEABILITY.md)). |
| CI (`ci.yml`) | fmt, clippy, tests on Linux/macOS/Windows, MSRV 1.90, wasm32 per crate, npm build + Node smoke test, UniFFI generation, Swift package + `swift test`, Android AAR, relay image + `/healthz`, requirements check. |
| Release (`release.yml`) | Tag `vX.Y.Z` → GitHub Release with relay binaries, npm tarball, Swift package + XCFramework, Android AAR, `SHA256SUMS`. GitHub Releases is the only publish target. Dry run verified 2026-11-03 ([run](https://github.com/elektrolytmangel/kith/actions/runs/41680667767)): every package built. |
| Dependencies | Current as of 2026-11-04: ed25519-dalek 3, sha2 0.11, rusqlite 0.41 (#20), automerge 0.12, Gradle 9.8.2, AGP 9.5, JNA 5.19.1, Actions. No open Dependabot PRs. |
| Template | `scripts/rename.py --name <n> --owner <o>` rebrands everything; tested on a copy. |

### What the library can do today (alpha, phases 1-5 and 6a done)

Requirements: 25 implemented, 9 partial, 8 accepted/proposed.

Works, on Rust, web (npm), Swift and Kotlin unless noted:
- signed, hash-linked changes; per-object history and fork detection; device keys that can be saved and restored;
- persistence: SQLite (Rust, Swift, Kotlin: `KithClient.open`), IndexedDB (web: `KithClient.open`);
- relay with device authentication (challenge/response); live sync of new changes between online devices
  (`kith-net` in Rust, `KithClient.connect` on web, `RelaySession` on Swift/Kotlin);
- catch-up: a new or returning device downloads what it lacks from one online peer (`catchUp`);
- invitations: `createOrg`, one-time invite links with short codes, admins, relay-checked certificates;
- write permissions: roles (viewer/editor/admin), per-type write rules, revocation; enforced on every device;
- end-to-end encryption (MLS, one group per org): create group, join request + admit, remove, key rotation,
  automatic commit catch-up, re-add and fork resolution; the relay sees only routing metadata;
- merging concurrent edits: JSON documents on Automerge on every platform (`createDocument`, `updateDocument`,
  `documentJson`); pluggable `Merger` in Rust.

**Not usable for real apps yet:**

| Gap | Effect | Requirement |
| --- | --- | --- |
| A device added by the losing side of an MLS fork must be admitted again | Rare (two admins at once); app sees `JoinRequested` | ADR 0004 |
| A removed device keeps a valid certificate for the relay (connects, sees metadata; cannot decrypt; its writes are revoked) | Relay-level revocation open | REQ-INV-004 |
| Read access is all-or-nothing per org | Subgroups are phase 6b | REQ-PERM-003 |
| No rate limits on the relay | Floodable | Phase 8 |
| Sync needs another device online | Offline-only devices can't catch up | REQ-RELAY-005 |
| Swift/Kotlin live-sync glue is only compiled in CI, never run against a relay | Unverified on devices | REQ-SYNC-004 |

Fine for: building and testing an integration. Not fine for: any real user data.

## Plan

Phases follow the [design doc](docs/design/0001-local-first-e2ee-sync.md#technology-stack-and-implementation-phases).
Work top to bottom; check items off here as they land.

### Next steps (in order)

Phases 1-3 and the repository setup are done; the checked items are in the Log and `git log`. What is left:

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
   - [ ] 6b Read-restricted subgroups (REQ-PERM-003).
6. **Phases 7-8**: files + always-on client, hardening.
7. **Small items**: mark the repository as a template (optional, owner only); run the Swift/Kotlin live-sync glue
   against a real relay on a device or emulator; consider a `v0.1.0-alpha.2` release (user's call) since `main` has
   many changes (persistence, merge, relay auth, live and catch-up sync) and the relay body format changed.

### Open questions for the user

- Release a `v0.1.0-alpha.2` now? Encryption, documents and range-based catch-up are on `main` (tags stay the user's).

### Open issues

- **One org per store**: objects carry no org, and catch-up offers every stored change to any org peer. Fine with one
  org per `KithClient`/database (the bindings' model); a device in two orgs must use two stores. Make it explicit
  (or scope objects by org) before apps rely on multiple orgs.

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
- **Relay bodies:** the first byte of a body is the kind (1 change, 2 have, 3 offer); a client from `v0.1.0-alpha.1` can't talk to current `main`.

## Working agreements

- Branch from `main`, open a PR, wait for CI. **Once every check is green the agent merges its own PR**
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
