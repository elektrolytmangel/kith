# 0026: History compaction

- **Status:** accepted (user decisions 2026-11-06, below); implemented
- **Date:** 2026-11-06
- **Requirements:** REQ-DATA-005 (also touches REQ-SYNC-002, REQ-PERM-004, REQ-STORE-002)

## Context

Every change is kept forever and sent to every new device. On the web the whole history sits in
memory (about 0.75 KiB per change; 50,000 changes take 6 s to open and 38 MiB). Compaction has to
shrink this without breaking what the rest of the system relies on:

- Changes are **signed and hash-linked**: a change names its parents by ID.
- **Reconciliation compares sets of change IDs**: a device that deleted a change would get it back.
- **Revocation keep lists** and the policy refer to change IDs.
- Compaction is a **format change**, so it belongs before the freeze point (ADR 0012).

## Decisions (user, 2026-11-06)

1. Only **admins** create snapshots.
2. Retention is set **per object type in the policy**; the default keeps everything.
3. No type needs its full history yet.
4. Built **before** the first beta.
5. First step covers **documents, raw objects and file chunks**.

## Design

1. **A snapshot is a signed change** on the object whose payload starts with the marker
   `kith/snapshot/v1\0` (`kith_core::snapshot`). It lists the IDs it **covers** (at most 10,000) and,
   for documents, a **bundle**: the payloads (Automerge changes) of the covered changes. Its parents
   are the covered changes nothing else covered builds on, so it sits after what it folded.
   The signed envelope is unchanged (no new `kith/change` version); apps cannot write the marker
   (`create` and `edit` refuse it).
2. **Accepting it:** a device accepts a snapshot whose author is an admin (or whose admin rights ended
   after the policy kept the change, like any seen change). It remembers the covered IDs, **deletes the
   covered changes** (`Store::delete`) and ignores them if they come again. The **creation change of an
   object is always kept**: it is what lists the object. Without the policy (not yet synced) the
   snapshot waits and is applied when the policy arrives; the covered set is rebuilt from the stored
   snapshots at start, so nothing extra is persisted.
3. **Reconciliation is unchanged.** The covered IDs are not in the ID set a device offers, so a new
   device is not asked for what nobody has. A device that still holds old changes sends them once;
   they are ignored, and it prunes as soon as the snapshot reaches it.
4. **Retention rules** (`Retention`, policy op `SetRetention`): `KeepAll` (default), `KeepLast(n)` (the
   newest *n* changes of each object stay), `KeepDays(n)`. `Client::compact` (admins) applies the
   rules: it takes the part of the causal order the rule lets go (for `KeepDays` with everything those
   changes build on) and writes snapshots of at most 400 KiB (so one fits a relay frame), up to 20 per
   object per call. A snapshot is made only if it folds at least 100 changes (`compact_min` changes
   that).
5. **Documents:** the merger applies a snapshot's bundle with the same checks as any change (ADR 0020),
   so the merged state is the same as before. Snapshots only repack: Automerge keeps every operation,
   but without a signed envelope, parent list and signature per change. Several snapshots of one object
   simply add up.
6. **Raw objects** (no merger): the covered changes are gone and the **heads stay**, so what the app reads
   (`history`) is the newest changes. `KeepLast(0)` keeps only the heads. Pick this only for types where
   old changes do not matter (registers, "latest wins" records), not for operation logs.
7. **Files:** `kith.file` objects can have new versions (`update_file`); a file reads its newest
   version. When a rule folds old versions, **their chunks are deleted** unless a kept version uses them.

## Trust

A device that has deleted the covered changes cannot check a snapshot against them, so snapshots
come from admins only, who already control roles and removal. A device that still has the changes could
check; it does not today. A snapshot by a non-admin is rejected like any change the policy forbids.

## Consequences

- Old history is gone from devices that prune: no undo or audit beyond the retention rule.
- **Older clients** do not know the marker: they treat a snapshot as an ordinary change (raw apps would
  see its bytes in `history`) and never prune. Upgrade every device before an admin sets a rule.
- Documents shrink by the envelope overhead only, not to the size of the current state: measured with
  120 small edits and the newest 10 kept, 50.7 KB of stored changes became 25.5 KB (half). A real squash needs a new Automerge document and is not done: concurrent
  edits built on old operations would be lost.
- One snapshot holds at most 10,000 covers and 400 KiB. A document whose bundle does not fit is folded
  in several snapshots; a single change larger than that cannot be folded.
- A snapshot made by an admin who is demoted before others saw it can become invalid, and its folded
  content with it, exactly like that admin's other unseen changes.
- Subgroup objects are folded by an admin who is in the subgroup.
- The policy object is not compacted.
- No new relay frame and no `PROTOCOL_VERSION` change; the store gains `delete` and `delete_chunk`
  (SQLite and IndexedDB delete the rows; an IndexedDB row whose key is not known yet is deleted at the
  next start).
