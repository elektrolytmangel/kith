# 0007: Scope in the change envelope

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-PERM-003 (also REQ-DATA-001, REQ-SYNC-002)

## Context

Changes did not say which org they belong to. Catch-up compared all stored IDs,
so a device in two orgs with one store would hand org A's data to org B's peers,
and the policy of one org would judge another org's changes. Read-restricted
subgroups (REQ-PERM-003) need the same separation inside one org. User decision
(2026-11-04): put the scope into the signed envelope.

## Decision

- `UnsignedChange::scope: Scope` is signed (domain tag `kith/change/v2`). A scope is
  `local` (this device only), an org (`<org hex>`), or a subgroup
  (`<org hex>/<name>`, used by 6b-2).
- An object keeps the scope of its first change; changes that try to move it are
  refused.
- `Store::scope_ids(scope)` feeds reconciliation, which runs per scope. Offers and
  broadcasts carry only that scope; a change arriving through an org's frames must
  belong to that org. `receive` refuses scopes of orgs this device is not in.
- The policy of the change's own org decides about it.
- `Client::create` uses the default scope: the only org this device belongs to,
  `local` before it joins one, or an error with several orgs (`create_in`). Data
  created before joining stays local.
- Formats: codec v2 (IndexedDB), SQLite schema 3. Older non-empty databases are
  refused: their envelopes no longer verify (alpha, hard break).

## Consequences

- One store can hold several orgs safely; the "one org per store" limit is gone.
- Subgroups can reuse the same mechanism with their own MLS group (6b-2).
- Local data does not move into an org on joining. An app that wants that copies it
  explicitly (for documents: create a new document from the JSON).

## Alternatives considered

- **One store per scope**: no envelope change, but every app juggles several
  clients and databases, and data is duplicated across them.
- **Scope only in store metadata, not signed**: a malicious peer could move a
  change into another scope.
