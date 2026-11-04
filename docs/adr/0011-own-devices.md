# 0011: A member adds its own devices

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-ID-002

## Context

Roles were per device: a user's second device was a separate member that an admin
had to invite and configure. The user decided (2026-11-04) that any member may admit
its **own** additional device, with the same user and role, and that this can never
make an admin. Admitting other people stays admin-only. The open question was who
signs the relay certificate of the new device. User decision: the member itself
(option A). The relay is stateless, so the certificate chain is all it can check.

## Decision

- **Certificate kind:** the flag byte of a membership certificate is now `0` member,
  `1` admin, `2` own device (it is signed, the length is unchanged). An *own-device*
  certificate is signed by a member for its own device.
- **Chains** have 1 to 3 certificates. The first is signed by the root and is never an
  own-device certificate. Each next one is issued by the device of the previous one.
  An admin may certify members and own devices, a plain member only own devices, and
  nobody certifies admins except the root. A device holding an own-device certificate
  cannot certify further devices, so the longest chain is root → admin → member →
  own device.
- **Policy op `LinkDevice { device }`** (kind 5), valid when authored by any current,
  non-linked member for a device that has no role or link yet. `Policy::links` maps
  the device to its user's device. The linked device has that member's role, capped at
  editor, and is revoked or demoted with it: `Restrict` on the member also keeps the
  linked devices' changes the admin had seen. An explicit role for the linked device
  (an admin's `SetRole` or `Restrict`) wins.
- **Own-device invites:** `create_own_device_invite` makes an invite link with
  `own=<issuer device>`. The claim frame gets an optional `to` (the issuer), because
  the issuer may not be an admin and claims normally go to the org's online admins.
  The relay delivers a claim with `to` only to that device, and only if it is an
  online certified member. `accept_claim` on the issuer adds the device to the MLS
  group, signs the own-device certificate, and appends `LinkDevice`.
- **Removal:** `remove_member` also removes the member's linked devices from the MLS
  group, and the revocation covers them through the link.

## Consequences

- The relay cannot tell an own-device certificate from a certificate a member issues
  for a stranger: it checks the structure, not intent. A malicious member can give a
  stranger a relay connection (routing metadata, no decryption: that needs MLS
  admission, and members ignore devices the policy does not know). This is the same
  class as REQ-INV-004 (relay-level revocation, still open).
- A linked device cannot add devices; the user links from a device that was admitted
  the normal way. Losing that one means restoring a backup (ADR 0010).
- Subgroups name devices, not users: a user's linked device is not in a subgroup
  automatically; an admin lists it.
- Old chains (1 or 2 certificates) stay valid and encode the same.

## Alternatives considered

- **An admin or the root signs** the own-device certificate through the policy: keeps
  chains at 2 but needs an admin online for every new phone.
- **Linked devices chain further:** unbounded chains; the 3-certificate cap is simpler.
