# 0026: History compaction

- **Status:** proposed (needs the user's answers, see *Questions*)
- **Date:** 2026-11-06
- **Requirements:** REQ-DATA-005 (also touches REQ-SYNC-002, REQ-PERM-004, REQ-STORE-002)

## Context

Every change is kept forever and sent to every new device. On the web the whole history sits in
memory (about 0.75 KiB per change; 50,000 changes take 6 s to open and 38 MiB). A busy document
therefore makes the app slower for ever. Compaction must shrink this without breaking what the rest
of the system relies on:

- Changes are **signed and hash-linked**: a change names its parents by ID.
- **Reconciliation compares sets of change IDs** (Negentropy). A device that deleted a change would
  get it back from the next peer.
- **Revocation keep lists** and the policy refer to change IDs.
- Documents are Automerge changes: the state after N changes can be saved as one Automerge document.
- Compaction is a **format change**, so it belongs before the freeze point (first beta, ADR 0012).

## Proposal

1. **A signed snapshot change.** A new change kind on a document object. Its payload is the object's
   saved state (for Automerge: the full document) and it lists the IDs it **covers**: the heads and,
   through them, all ancestors up to a cut. It is an ordinary signed, scoped change, validated like
   any other (role, write rules).
2. **Tombstones keep the ID sets stable.** A device that accepts a snapshot may delete the covered
   changes' bodies and keeps only their 32-byte IDs (a "covered" table). Reconciliation counts them as
   present, so nobody re-sends them; keep lists and parent links still resolve. That is roughly 20 times
   less memory than the changes themselves. A later change whose parent is covered is accepted.
3. **Retention comes from the policy.** An admin sets, per object type, how much history is kept:
   `keep everything` (the default), `keep the last N changes`, `keep D days`, or `snapshot only`. The
   rule is a new policy op (`SetRetention`), so every device reads the same one. Devices create
   snapshots when a rule says so; an admin can also trigger one.
4. **New devices and backups** receive the snapshot plus the changes after it, not the old changes.
5. **Files** stay as they are in this step. Chunks of file objects that a snapshot no longer needs can
   be removed in a later step.
6. **Not compacted:** the policy object and anything of type `local`.

## Trust

Someone who has pruned the covered changes cannot check that the snapshot equals their fold. The
snapshot could drop other people's edits. Options:

- **A. Snapshots only from admins.** Simple; members trust admins (they already trust them with roles
  and removal). Devices that still hold the full history can verify and warn on a mismatch.
- **B. Any editor, verified by a covered-set hash.** The snapshot carries a hash over the covered IDs
  (sorted), so a device with the history can verify it; those without trust the author. Needs
  conflict rules for two snapshots of the same object.

## Consequences

- Old history is gone from devices that prune: no undo or audit beyond the retention rule. Types that
  need it keep everything.
- The sync protocol changes (covered IDs, snapshot payload), so older clients cannot read snapshot
  objects: from the first beta this needs a compatibility rule (ADR 0012).
- Memory and open time of a web store are bounded by retention, not by age.
- Needs a store migration path (SQLite schema, IndexedDB version) and golden tests for the snapshot
  envelope.

## Questions for the user

1. **Who may compact?** Admins only (A, recommended) or any editor (B)?
2. **Retention:** is the per-type policy rule (`keep everything` by default, else last N changes / D
   days / snapshot only) the right level, or should it be one org-wide setting?
3. **Does any app type need full history** (audit, undo)? Then those types stay on `keep everything`.
4. **When?** Before the first beta (recommended: it is a format change) or after?
5. **Scope of the first step:** documents only (recommended), or also raw byte objects (where the
   newest change simply wins) and file chunks?
