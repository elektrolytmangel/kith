# 0005: Org root key, membership certificates and invitations

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-ID-003, REQ-INV-001..003, REQ-RELAY-004

## Context

Phase 5 adds invitations. The relay must be able to tell members from strangers
(REQ-RELAY-004) while storing nothing, only admins may admit devices, and a
leaked or intercepted invite must not let an attacker in unnoticed. The design
doc describes the flow but not the formats. User decisions (2026-11-04): org ID =
root public key; only admins invite and admit; invites are single-use and
expiring with an optional short code; no relay buffer.

## Decision

- **Org root key:** a fresh Ed25519 key per organization, created and held by the
  creating device. The **org ID is its public key** (64 hex characters). Not the
  creator's device key (as REQ-ID-003 first said): otherwise one device could
  create only one org, and losing that device would also lose the org's identity
  for every other org it created.
- **Membership certificates** (`kith_core::membership`): `org, device, issuer,
  admin, issued_ms`, signed by `issuer` under the domain tag
  `kith/membership/v1`. A chain is the device's certificate, preceded by its
  issuer's certificate if the issuer is not the root: root → device, or root →
  admin → device. Only the root sets `admin`. The relay verifies the chain on
  `announce` against the org ID alone, without state.
- **Invites:** `kith://invite/v1?org=…&relay=…&token=…&secret=…&expires=…`.
  Single-use, stored only on the issuing admin's device, so only that device can
  admit the claimer and two admins can never both add it (no MLS fork).
- **Claim:** the new device sends its MLS KeyPackage and
  `HMAC-SHA256(secret, "kith/invite-claim/v1" ‖ token ‖ SHA-256(KeyPackage))`. A
  relay without the secret cannot swap in its own KeyPackage.
- **Short code:** six digits from the same HMAC construction under another label.
  Both screens can show it; if they match, the admin is adding the device the user
  holds, not one that copied the link. The app decides whether to require it.
- **Pending devices:** an authenticated device without a valid chain may only send
  invite claims and receive direct messages for that org. It does not appear in
  presence and cannot broadcast.

## Consequences

- Org IDs are no longer names; apps keep a display name (for example in a
  document) next to the ID.
- The root key is a single point: if the creating device is lost, no new admins can
  be made (existing admins can still invite). Root key recovery stays an open
  question (ADR index).
- Revocation is not part of the certificate: a removed device keeps a valid chain
  for the relay (it can see metadata and connect) but cannot read anything, since
  it was removed from the MLS group. A revocation list belongs in the policy object
  (phase 6).

## Alternatives considered

- **Free-form org IDs with the root key in the proof:** the relay cannot tell the
  right root key from a fake one without storing state.
- **Device key as root key:** simpler, but one org per device, see above.
- **Invite secret as an MLS PSK / password-authenticated key exchange:** stronger
  against offline guessing, but the secret is 256 random bits, so HMAC suffices.
