# Relay server

### REQ-RELAY-001: Relay persists nothing

- **Priority:** must | **Phase:** 2 | **Status:** partial | **Verify:** test | **Source:** design §Relay

The relay must keep routing state in RAM only and write no message content,
metadata or keys to disk. Disconnecting must remove all state about a device.

### REQ-RELAY-002: Broadcast to online members

- **Priority:** must | **Phase:** 2 | **Status:** implemented | **Verify:** test | **Source:** design §Message types

A broadcast must reach every online device of the organization except the
sender.

### REQ-RELAY-003: Drop messages for offline devices

- **Priority:** must | **Phase:** 2 | **Status:** implemented | **Verify:** test | **Source:** design §Message types

Messages to offline devices must be dropped, and the sender must be told which
devices received them.

### REQ-RELAY-004: Device authentication and membership proofs

- **Priority:** must | **Phase:** 2 | **Status:** implemented | **Verify:** test | **Source:** design §Connection

Devices must prove key ownership by signing a server challenge and announce
organizations with proofs the relay can check without decrypting anything.

Challenge/response with the device key (nothing else is accepted before it,
unauthenticated connections time out, a reconnecting device replaces its old
connection). Membership proofs are certificate chains checked against the org ID,
which is the org root public key (ADR 0005); devices without one are pending.

### REQ-RELAY-005: Handover buffer

- **Priority:** could | **Phase:** 7 | **Status:** rejected | **Verify:** test | **Source:** design §Relay, open question

The relay may buffer messages for a device that disconnected in the last few
seconds (e.g. 30 s), in RAM only. Pending ADR.

Rejected (user, 2026-11-04): the relay keeps "stores nothing"; the always-on client
(REQ-SYNC-006) is the reliable catch-up partner instead.

### REQ-RELAY-006: Abuse limits

- **Priority:** must | **Phase:** 8 | **Status:** partial | **Verify:** test | **Source:** design §Abuse limits

The relay must enforce a maximum frame size and rate limits per device and per
organization.

### REQ-RELAY-007: Wake-up pushes

- **Priority:** should | **Phase:** 7 | **Status:** proposed | **Verify:** manual | **Source:** design §Push

The relay should be able to send content-free APNs/FCM pushes to wake phones.
