# 0006: Policy object, fixed roles, revocation with keep lists

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-PERM-001, REQ-PERM-002, REQ-PERM-004, REQ-INV-004

## Context

Any member can send anything into the MLS group, so write permissions must be
checked by every client on every change. The design doc wants a policy object
"rooted in the org root key" and "the policy as of the change's parents". But a
change's parents are inside its own object, so a data change says nothing about
which policy its author had seen. User decisions (2026-11-04): a signed policy
object; fixed roles admin / editor / viewer; revocation wins; read-restricted
subgroups later.

## Decision

- **One policy object per org**: type `kith.policy`, ID derived from the org ID.
  Each change holds one op:
  - `Genesis`: the creator's root-signed admin certificate (ADR 0005).
  - `SetRole`: raise a role. Admin needs a root-signed certificate, so only the
    root makes admins, as in phase 5.
  - `SetRule`: the minimum write role per object type (default editor).
  - `Restrict`: revoke or demote, with a **keep list**.
- **Deterministic fold** (`Policy::fold`): ops are applied in causal order.
  Concurrent ones are ordered by seniority: the creator first, then admins in the
  order they became admins, then by change ID. An op counts only if its author is
  an admin at that point. The creator can't be restricted, and an admin can't
  restrict a more senior admin. So two admins revoking each other resolve the same
  way everywhere, and the root always wins.
- **Revocation wins, via keep lists**: restricting a device lists the change IDs
  of it that the admin had seen. Those stay valid. Every other change by that
  device is judged by its new role. This expresses "causally before the
  revocation" without cross-object causality in the change envelope. A device
  cannot backdate past it, because the list names exact hashes.
- **Validation** (`Client::receive`): a change counts if its author's role (or
  the keep list) allows its type and no parent is rejected. Members not named in
  the policy are editors; viewers can write only types whose rule is `viewer`.
  Local writes that would not count are refused up front (`Forbidden`).
- **Quarantine, not deletion**: rejected changes are stored but kept out of
  history, merging and new edits' parents. They are still passed on in catch-up,
  so every device sees them, rejects them and their dependents the same way, and
  a later grant can make them count. This is how we read REQ-PERM-002's "neither
  store nor forward": invalid changes never take effect anywhere. Dropping them
  instead would make the outcome depend on arrival order: a change that arrives
  before the grant that allows it would be lost on that device only.
- **Re-check on every policy change**: stored changes are re-validated when a
  policy change arrives. Policy changes are rare, and the full pass is O(history).
- `remove_member` removes from MLS **and** revokes (REQ-INV-004).

## Consequences

- Apps get roles and per-type rules with no app-side checks, the same on all
  platforms.
- A device that lacks the policy object yet (just joined, before catch-up)
  enforces nothing until it arrives; it then re-checks everything.
- Members can make honest peers store junk that never counts (quarantine). Rate
  limits and pruning are phase 8.
- The policy assumes one org per store (PLAN open issue).
- Dependents of rejected changes are rejected, not rebased. Their authors redo the
  edit on a valid head; for JSON documents a new `updateDocument` does it.

## Alternatives considered

- **Certificates only** (roles in certificates, separate revocation records): no
  per-type rules, and every role change needs a new certificate.
- **Policy heads in every change envelope** ("as of parents" literally): exact,
  but it changes the signed envelope and every store, and still needs keep lists
  for offline changes.
- **Timestamp cut-off for revocations**: a revoked device could backdate changes.
