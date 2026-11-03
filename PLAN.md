# Plan and status

The single place to see where kith stands, what was decided, and what comes
next. **Read this first when you pick up work. Update it whenever you make a
plan or finish a piece of work** (see [CLAUDE.md](CLAUDE.md)).

- **Last updated:** 2026-11-03
- **Version:** 0.1.0 in `Cargo.toml`, **not released** (no tags, no GitHub Release yet)
- **Repository:** <https://github.com/elektrolytmangel/kith> (public, MIT)

## Where things stand

### Done

| Area | State |
| --- | --- |
| Repository structure | Rust workspace (`crates/`), relay server (`apps/relay-server`), bindings (UniFFI → Swift/Kotlin, wasm-bindgen → npm), docs, requirements, ADRs. See [README](README.md). |
| Requirements as code | 41 requirements in `docs/requirements/`, traced to tests by `scripts/reqs.py` ([TRACEABILITY.md](docs/requirements/TRACEABILITY.md)). |
| CI (`ci.yml`) | fmt, clippy, tests on Linux/macOS/Windows, MSRV 1.88, wasm32 per crate, npm build + Node smoke test, UniFFI generation, Swift package + `swift test`, Android AAR, relay image + `/healthz`, requirements check. |
| Release (`release.yml`) | Tag `vX.Y.Z` → GitHub Release with relay binaries, npm tarball, Swift package + XCFramework, Android AAR, `SHA256SUMS`. GitHub Releases is the only publish target. Dry run verified 2026-11-03 ([run](https://github.com/elektrolytmangel/kith/actions/runs/41680667767)): every package built. |
| Dependencies | Current as of 2026-11-03: ed25519-dalek 3, sha2 0.11, Gradle 9.8.2, AGP 9.5, JNA 5.19.1, Actions bumped (#3, #7, #9, #10). |
| Template | `scripts/rename.py --name <n> --owner <o>` rebrands everything; tested on a copy. |

### What the library can do today (phase 1 skeleton)

Requirements: 7 implemented, 12 partial, 22 accepted/proposed.

Works: signed, hash-linked changes; per-object history and fork detection;
in-memory store; device keys; naive reconciliation; relay routing table; relay
WebSocket server; the `create` / `edit` / `history` API on every platform.

**Not usable for real apps yet:**

| Gap | Effect | Requirement |
| --- | --- | --- |
| Storage is in memory only | Data lost on restart | REQ-STORE-001 |
| Bindings make a new device key per launch (`from_secret_bytes` exists only in Rust) | New identity every start | REQ-PLAT-002, REQ-PLAT-003 |
| `Transport` is only a trait; no WebSocket client | Clients can't talk to the relay | REQ-SYNC-004 |
| Relay has no device authentication | Don't expose it publicly | REQ-RELAY-004 |
| No encryption (MLS) | Payloads are not end-to-end encrypted | REQ-ENC-001..004 |
| Concurrent edits stay forked (no CRDT merge) | No conflict-free merging | REQ-DATA-004 |
| No permission checks on incoming changes | Any device can write anything | REQ-PERM-002 |

Fine for: wiring the API into an app and checking the platform integration.
Not fine for: any real user data.

## Plan

Phases follow the [design doc](docs/design/0001-local-first-e2ee-sync.md#technology-stack-and-implementation-phases).
Work top to bottom; check items off here as they land.

### Next steps (in order)

1. **First pre-release `v0.1.0-alpha.1`**, so projects can install it.
   - [ ] PR: version `0.1.0-alpha.1` in `Cargo.toml` (`[workspace.package]` and the internal
         `[workspace.dependencies]` entries), CHANGELOG *Unreleased* → `0.1.0-alpha.1`.
   - [ ] After merge, the user tags `v0.1.0-alpha.1`. The workflow marks versions with `-` as pre-release.
2. **Repository settings** (need the owner or explicit approval):
   - [ ] Create label `requirement` (the Requirement issue form applies it; it doesn't exist).
   - [ ] Branch protection on `main`: require the CI checks.
   - [ ] Enable private vulnerability reporting (Settings → Code security). Owner only.
   - [ ] Optional: mark the repository as a template.
3. **Phase 1, Local core** (makes it usable in a real app):
   - [ ] REQ-STORE-001: SQLite `Store` in `kith-store` (native); IndexedDB store for the web package.
   - [ ] Key restore in bindings: expose key seed in/out in `bindings/ffi` and `bindings/wasm`
         (Keychain / Android Keystore / IndexedDB are the app's job, see `Signer`).
   - [ ] Database path / store selection in the binding constructors (`TODO(phase 1)` in `bindings/ffi/src/lib.rs`, `bindings/wasm/src/lib.rs`).
   - [ ] REQ-DATA-004: Automerge objects so concurrent edits merge.
4. **Phase 2, Relay and live sync**: WebSocket `Transport` (tokio native, browser WebSocket on web),
   REQ-RELAY-004 device auth (challenge/response in `apps/relay-server/src/main.rs` TODOs), REQ-SYNC-004 live updates.
5. **Phase 3, Catch-up sync**: finish REQ-SYNC-001..003.
6. **Phase 4, Encryption (MLS / OpenMLS)**: REQ-ENC-001..004. **Required before any real user data.**
7. Phases 5–8: invitations, permissions, files + always-on client, hardening (see requirements).

### Open questions for the user

- Start phase 1 with SQLite store + key restore? (recommended: makes real app integration possible)
- First release as `v0.1.0-alpha.1` (recommended) or `v0.1.0`?

### Open issues

- **macOS jobs get cancelled before starting** (0 steps): seen 4× on 2026-11-03 (PR #3, PR #10,
  release dry run, `main` after the #10 merge). Re-running always passed. Not yet investigated; possibly
  runner capacity or a macOS concurrency limit when CI and Release run at the same time.
  Workaround: *Re-run failed jobs*.

## Decisions (don't re-litigate without the user)

| Decision | Why | Where |
| --- | --- | --- |
| Name `kith`, owner `elektrolytmangel` | User's choice; repo renamed to `kith` | `rename.py` replaces both |
| License MIT, copyright Marc Muehlheim | User's choice | `LICENSE`. `authors` in Cargo.toml stays "kith contributors" (user said no) |
| Publish to GitHub Releases only | User: "not more is needed". No npm/Maven/ghcr/crates.io pushes | `release.yml`, [releasing.md](docs/guides/releasing.md) |
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

## Working agreements

- Branch from `main`, open a PR, wait for CI. **The user merges** (agent merges and force-pushes are blocked).
- `gh` is logged in as `finocchio-42` (push access, not admin).
- Commits end with the `Co-Authored-By` line; PR descriptions follow `.github/pull_request_template.md`.

## Log

- **2026-11-03**: Structure, CI, release pipeline (PR #1). License, Gradle wrapper, owner URLs, Swift CI.
  Dependabot review: merged #3, #7; replaced #2/#4/#5/#6/#8 with #9 (ed25519-dalek 3 + sha2 0.11) and
  #10 (Gradle 9 + AGP 9 + Android CI, fixed stripped-metadata bug). Release dry run: all packages build.
  This plan written.
