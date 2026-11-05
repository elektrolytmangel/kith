# 0013: Relay-level revocation

- **Status:** accepted (RAM-only default; optional persistence: [ADR 0014](0014-optional-revocation-persistence.md))
- **Date:** 2026-11-05
- **Requirements:** REQ-INV-004, REQ-RELAY-001, REQ-RELAY-004

## Context

`remove_member` removes a device from MLS (it cannot decrypt) and revokes it in the policy (its writes
are rejected). The relay, however, checks only the certificate chain, which does not expire, so a removed
device could still connect and see routing metadata (who is online). The relay cannot read the encrypted
policy, and it stores nothing on disk.

## Decision (user choice, 2026-11-05)

- **Revocation notice** (`kith_core::membership::Revocation`): org, device, issuer, time, signature under
  `kith/revoke/v1`, plus the issuer's chain. Valid only if the issuer is an admin of the org, so the relay
  checks it from the org ID alone, without new trust.
- **Transport:** an optional list `Membership.revoked` in `announce`. No new frame; clients that do not
  know the field ignore it.
- **Relay:** verifies notices, keeps revoked devices per org **in RAM only** (at most 10,000 per org,
  256 notices per announce), removes affected online devices (`revoked` error, presence update) and
  refuses their later announces. A chain is affected if **any** certificate in it is for a revoked
  device, so a member's own devices go with it (ADR 0011). Pending devices cannot feed the list.
- **Client:** `remove_member` signs the notice, saves it in the store (`revocations` meta) and ends with an
  `announce` frame carrying it. Every later announce of that device repeats it, so a restarted relay learns
  it again once that admin reconnects.

## Consequences

- The relay still stores nothing on disk; after a restart a removed device can connect until an admin
  that issued the notice announces again.
- Only the issuing admin repeats a notice. Spreading notices to other admins and the always-on client
  (so they can repeat them if the issuer is gone) is open work.
- Revocation is permanent per device key. A removed device that wants back needs a new device key and
  an invite.

## Alternatives considered

- **Short-lived certificates:** stateless, but offline devices drop out until renewed and revocation lags.
- **Relay persists a revocation list:** robust, but breaks "stores nothing" (REQ-RELAY-001).
