# 0014: Optional persistence of revocation notices

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-INV-004, REQ-RELAY-001
- **Amends:** [ADR 0013](0013-relay-revocation.md) (RAM only)

## Context

ADR 0013 keeps revocation notices in RAM. After a relay restart a removed device can connect again until the
issuing admin announces. A relay operator who already runs durable state (the Azure Table with the approved
orgs, REQ-RELAY-008) can close that gap.

## Decision (user request, 2026-11-05)

Persistence is an **opt-in feature of the relay**, off by default, so the default relay still stores nothing.

- `KITH_RELAY_PERSIST_REVOCATIONS=true` turns it on. It needs a store that can keep notices; today that is the
  Azure Table state (`azure-state` feature). Without one the relay refuses to start.
- Storage: table `revocations` (`KITH_RELAY_AZURE_REVOCATIONS_TABLE`), PartitionKey = org ID, RowKey = revoked
  device ID, column `Notice` = the signed notice (hex).
- The stored value is the same signed notice as on the wire. It is **verified again against the org ID on
  load**, so tampered storage cannot revoke a device nobody revoked, and cannot add a revocation the org admin
  did not sign. Deleting rows can only un-revoke, which the issuing admin's announces repair.
- Load at start (a failed read exits, like the allowlist). New notices are written by a background task
  (5 attempts with backoff, then logged); the notice stays in RAM either way.
- Notices are never deleted by the relay (revocation is permanent per device key, ADR 0013).

## Consequences

- With the option on, the relay stores org IDs and device IDs of revoked devices and the signed notices. This is
  more than "stores nothing" (REQ-RELAY-001) and is documented as such; message content is never stored.
- Closes the restart gap for notices the relay accepted. Spreading notices to other admins stays open.
- The `revocations` table needs the same role as the allowlist table (*Storage Table Data Contributor*).
