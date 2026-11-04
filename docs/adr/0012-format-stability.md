# 0012: Format versions and compatibility rules

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-DATA-001, REQ-STORE-002

## Context

alpha.1 data does not work on alpha.2, and nothing told users except the changelog.
Before a release that people rely on, every persisted or exchanged format needs a
version, a rule for changing it, and a test that fails when it changes by accident.

## Inventory

| Format | Version marker | Where | Guard |
| --- | --- | --- | --- |
| Signed change envelope | domain tag `kith/change/v2` | `kith-core/src/change.rs` | golden test `change_v2_format_is_frozen` |
| Stored change encoding | version byte `2` | `kith-store/src/codec.rs` | golden test `encoding_v2_is_frozen` |
| SQLite schema | `PRAGMA user_version` = 3 | `kith-store/src/sqlite.rs` | refuses older/newer (tests) |
| IndexedDB | database version 3 | `bindings/wasm/src/idb.rs` | smoke test |
| Relay protocol | `PROTOCOL_VERSION` = 1 | `kith-protocol` | hello check |
| Relay auth, invite claim/code, membership, policy, orgs, file chunk | domain tags `…/v1` | respective modules | unit tests |
| MLS state in the store | `kith/mls-state/v2` | `kith-crypto/src/group.rs` | unit tests |
| Backup file | magic `kith-backup/v1` | `kith-client/src/backup.rs` | unit tests |

## Decision

1. **Every format change bumps its marker.** Never change a format in place. A domain
   tag change also needs a new golden value in the guard test, written in the same PR
   as the bump.
2. **Each break is listed under `### Breaking` in the changelog** and, for protocol,
   envelope or crypto, has an ADR.
3. **Guards:** the golden tests above pin the bytes of a fixed change. A failing one
   means a silent break; fix the code, or bump the marker deliberately.
4. **Before the freeze point** (alphas): breaks need no migration; stores refuse
   data they cannot read with a clear error (already true for SQLite).
5. **From the freeze point** (the first beta, `0.2.0-beta.1`; user decision 2026-11-04): a release can read
   the formats of the previous release (storage migration on open, backups still
   restore), and the relay accepts clients of the previous `PROTOCOL_VERSION`.
   Breaking beyond that needs a major version.

## Consequences

- Accidental format changes fail CI instead of corrupting users' data.
- Until the first beta, rule 4 applies.
