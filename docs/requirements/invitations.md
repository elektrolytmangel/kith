# Invitations and onboarding

### REQ-INV-001: One-time invitations

- **Priority:** must | **Phase:** 5 | **Status:** implemented | **Verify:** test | **Source:** design §Invitations

An admin device must be able to create a one-time, expiring invite (link or
QR) containing org ID, root public key, relay address and a random secret.

### REQ-INV-002: Claim and verification

- **Priority:** must | **Phase:** 5 | **Status:** implemented | **Verify:** test | **Source:** design §Invitations

A new device must claim the invite with a proof derived from the secret; the
admin device must verify proof and expiry before adding it to the MLS group.

### REQ-INV-003: Short-code verification

- **Priority:** should | **Phase:** 5 | **Status:** implemented | **Verify:** manual | **Source:** design §Invitations

Both devices should be able to display a short code to compare, defeating a
relay that substitutes its own device.

### REQ-INV-004: Device and user removal

- **Priority:** must | **Phase:** 5 | **Status:** implemented | **Verify:** test | **Source:** design §Removing

An admin must be able to remove a device (MLS remove with key rotation) and
revoke it in the policy object; later changes by that key must be rejected.

`remove_member` removes the device from MLS and revokes it in the policy (ADR 0006).
It also signs a revocation notice (ADR 0013): the relay checks it against the org ID, holds
it in RAM, drops the device (and devices certified through it) and refuses its certificate
until the relay restarts; the admin repeats the notice on every announce.
