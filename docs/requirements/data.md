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

- **Priority:** must | **Phase:** 1 | **Status:** partial | **Verify:** test | **Source:** design §Concurrency

Edits must never wait for a lock. Concurrent edits must be detected (shared
parent) and merged deterministically on every client (Automerge by default,
per-type rules otherwise).

### REQ-DATA-005: Compaction

- **Priority:** should | **Phase:** 8 | **Status:** proposed | **Verify:** test | **Source:** design §Risks

Clients should support snapshots plus pruning of old changes under a per-type
policy agreed by the organization.

### REQ-STORE-001: SQLite local store

- **Priority:** must | **Phase:** 1 | **Status:** partial | **Verify:** test | **Source:** design §Local storage

Native clients must store changes append-only in SQLite with a materialized
objects table that is rebuildable from changes.

`kith_store::SqliteStore` (feature `sqlite`) implements this. Still open: wiring it
into the bindings, and the IndexedDB store for web.

### REQ-STORE-002: Pluggable storage

- **Priority:** should | **Phase:** 1 | **Status:** partial | **Verify:** review | **Source:** ADR-0001

Storage must sit behind a trait so platforms (e.g. IndexedDB on web) and apps
can provide their own backend.
