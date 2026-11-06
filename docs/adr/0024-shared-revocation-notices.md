# 0024: Sharing revocation notices between admins and the always-on client

- **Status:** accepted
- **Date:** 2026-11-06
- **Requirements:** REQ-INV-004
- **Amends:** [ADR 0013](0013-relay-revocation.md)

## Context

A relay that forgets its revocation list (RAM-only by default) learns it again from the notices
that devices repeat on every announce. Only the admin who issued a notice repeated it, so if that
admin was gone for good, a restarted relay admitted the removed device again.

## Decision

- **A new inner message `Notices` (kind 9)**, encrypted in the org's MLS group, carries notices
  as hex lines (at most 64 per message).
- **When shared:** `remove_member` broadcasts the new notice right after the commits (the removed
  device is already out of the group). A device answering a catch-up request (`Query` in the org
  scope) also sends the notices it holds, so an admin or always-on client that joined later learns
  them.
- **Who keeps them:** admins and the always-on client only (they repeat notices on announce). A
  receiver verifies every notice on its own (`Revocation::verify` for this org: signature and an
  admin or root issuer), skips duplicates and keeps at most 256 per org, the relay's limit per
  announce. A plain member keeps nothing.
- **Relay rules are unchanged** (ADR 0018): the relay still decides what a notice may do.

## Consequences

- Any admin or the always-on client can restore the relay's list after a restart, so the issuing
  admin no longer has to come back. Persistence (ADR 0014) stays the stronger option.
- Notices of devices that were removed before this change reach later admins only if a holder
  answers their catch-up.
- A malicious admin can already revoke members (that is their role); sharing adds nothing to
  what they can do.
- Old clients reject the unknown message kind with a `Rejected` event and keep working.
