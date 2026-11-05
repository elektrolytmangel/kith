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

- **Priority:** must | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** design §Abuse limits

The relay must enforce a maximum frame size and rate limits per device and per
organization.

`kith_relay_server::Limits` (env `KITH_RELAY_*`): WebSocket message cap, token buckets
per connection (frames, bytes) and per org (routed frames), a connection cap, and
disconnecting persistent abusers. Clients cap quarantined changes per author
(`MAX_QUARANTINE`).

### REQ-RELAY-007: Wake-up pushes

- **Priority:** should | **Phase:** 7 | **Status:** proposed | **Verify:** manual | **Source:** design §Push

The relay should be able to send content-free APNs/FCM pushes to wake phones.

### REQ-RELAY-008: Approved organizations only

- **Priority:** should | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** operator request (2026-11-05)

A relay operator must be able to restrict a relay to a list of approved
organizations. An `announce` for any other org is refused with `org-not-allowed`,
pending devices included, so nobody can route there. Unset or empty serves every
org (local use, tests).

`KITH_RELAY_ALLOWED_ORGS`: org IDs (hex root public keys) separated by commas or
whitespace. Read at start.

Alternatively the list lives in an Azure Table (feature `azure-state`; `KITH_RELAY_AZURE_STORAGE_*`),
which the relay re-reads every `KITH_RELAY_ALLOWLIST_REFRESH_SECS` (default 30). Orgs
removed from the list lose their online devices (`org-not-allowed`). An empty or
missing table approves nobody; a failed read keeps the last list.
