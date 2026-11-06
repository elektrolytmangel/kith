# Data model and storage

### REQ-DATA-001: Signed, hash-linked changes

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Data model

Every change must carry a content hash (`change_id`) and an Ed25519 signature
by its author over all fields. Clients must reject changes whose hash or
signature does not verify.

### REQ-DATA-002: Opaque, typed payloads

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Requirements

Payloads must be opaque bytes with an application-defined type tag. The core
must not interpret payloads.

### REQ-DATA-003: Per-object history

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Data model

Each change must name the changes it builds on (`parents`), so every object
has a complete change graph. History must never be rewritten; restoring an
old version is a new change.

### REQ-DATA-004: Lock-free concurrent edits

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Concurrency

Edits must never wait for a lock. Concurrent edits must be detected (shared
parent) and merged deterministically on every client (Automerge by default,
per-type rules otherwise).

`kith_merge::Merger` with the Automerge implementation does this (see
[ADR 0003](../adr/0003-merge-automerge-default-pluggable.md)). All bindings expose it
as JSON documents: `createDocument`, `updateDocument` (RFC 7396 merge patch) and
`documentJson`. Changes are checked before Automerge applies them, and documents nest
at most 100 levels ([ADR 0020](../adr/0020-checked-automerge-changes.md)).

### REQ-DATA-005: Compaction

- **Priority:** should | **Phase:** 8 | **Status:** proposed | **Verify:** test | **Source:** design §Risks

Clients should support snapshots plus pruning of old changes under a per-type
policy agreed by the organization.

**Not built yet (decided 2026-11-06: later).** Until then history only grows; the guides tell adopters to plan for it.
Design proposed in [ADR 0026](../adr/0026-history-compaction.md) (signed snapshots, tombstones, per-type retention in the policy); waiting for decisions.

### REQ-DATA-006: Encrypted backups

- **Priority:** should | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** design §Risks (all devices lose data)

A device must be able to export its data, files and identity as a
passphrase-encrypted backup and restore it on new hardware, rejoining its groups
without reusing old encryption keys ([ADR 0010](../adr/0010-encrypted-backups.md)).

### REQ-DATA-007: List objects

- **Priority:** must | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** this repo

An app must be able to list the objects a device knows (optionally of one type),
in every binding, so it can build its views after a restart or a catch-up without
keeping its own index of object IDs.

### REQ-STORE-001: SQLite local store

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Local storage

Native clients must store changes append-only in SQLite with a materialized
objects table that is rebuildable from changes.

`kith_store::SqliteStore` (feature `sqlite`) implements this. Swift and Kotlin use it
through `KithClient.open`. The web package uses IndexedDB
(write-through to an in-memory store, since `Store` is synchronous).

### REQ-STORE-002: Pluggable storage

- **Priority:** should | **Phase:** 1 | **Status:** implemented | **Verify:** review | **Source:** ADR-0001

Storage must sit behind a trait so platforms (e.g. IndexedDB on web) and apps
can provide their own backend.

### REQ-STORE-003: Stored secrets are encrypted

- **Priority:** must | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** ADR-0021

Secrets the client keeps in its store (the org state, which can hold the org root
key, and the MLS group state) must be encrypted with a key only the device key can
produce, so a copy of the store alone reveals no key. Files the native store creates
must be readable by their owner only.
