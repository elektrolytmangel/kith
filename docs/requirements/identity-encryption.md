# Identity and encryption

### REQ-ID-001: Device key is the device identity

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** test | **Source:** design §Identity

Each device must create an Ed25519 key pair on first launch. Its public key is
the device ID everywhere in the system. The secret must be restorable from
platform secure storage and must never be logged or transmitted.

### REQ-ID-002: Users own multiple devices

- **Priority:** must | **Phase:** 6 | **Status:** accepted | **Verify:** test | **Source:** design §Identity

The policy object must map device keys to users and users to roles, so one
user can have several devices.

### REQ-ID-003: Organization root of trust

- **Priority:** must | **Phase:** 5 | **Status:** implemented | **Verify:** test | **Source:** design §Identity

Creating an organization must create its root key, held by the creator's device;
the root public key is the org ID, and the creator's device is the first admin
(ADR 0005). Every member must learn the root public key through its invitation.

### REQ-ENC-001: End-to-end encryption with MLS

- **Priority:** must | **Phase:** 4 | **Status:** implemented | **Verify:** test | **Source:** design §Identity

Every organization must be one MLS group (RFC 9420). All change messages must
be MLS application messages; the server must never hold keys.

### REQ-ENC-002: Commit log for catch-up

- **Priority:** must | **Phase:** 4 | **Status:** implemented | **Verify:** test | **Source:** design §Sync

Every client must store the recent MLS commit log so returning peers can fetch
commits they missed, and must apply commits in epoch order.

### REQ-ENC-003: Periodic key rotation

- **Priority:** should | **Phase:** 4 | **Status:** partial | **Verify:** test | **Source:** design §Identity

Members should rotate their own leaf key (MLS update) periodically and after a
long pause.

### REQ-ENC-004: Re-add fallback

- **Priority:** must | **Phase:** 4 | **Status:** implemented | **Verify:** test | **Source:** design §Sync fallbacks

If a client cannot obtain the commits it missed, an online member must be able
to re-add it with a fresh MLS Welcome.
