# 0019: Relay resource limits

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-RELAY-006
- **Amends:** [ADR 0013](0013-relay-revocation.md), [ADR 0018](0018-relay-revocation-rules.md)

## Context

REQ-RELAY-006 limits what the relay accepts: frames per connection and per org, message size and
the number of connections. This decision extends the limits to what the relay keeps per connection
and per org, and to how long it keeps a connection, so its memory and CPU use stay bounded by
configuration.

## Decision

- **Bounded outboxes.** Each connection has a bounded queue: at most 1024 frames and
  `KITH_RELAY_MAX_QUEUED_BYTES` (16 MiB). A frame for a device whose outbox is full is dropped and
  left out of the sender's receipt; the device catches up by sync. One frame always fits into an
  empty outbox.
- **Write timeout.** A socket that takes longer than `KITH_RELAY_WRITE_TIMEOUT_SECS` (10) to accept
  a frame closes the connection.
- **Idle timeout.** The relay pings every connection every third of `KITH_RELAY_IDLE_TIMEOUT_SECS`
  (120). A connection that sends nothing, not even pongs, for that long is closed. WebSocket clients
  answer pings themselves.
- **Connections per address.** At most `KITH_RELAY_MAX_CONNECTIONS_PER_IP` (100) open connections per
  client address (IPv6 per /64); more get HTTP 429. Behind a proxy, `KITH_RELAY_CLIENT_IP_HEADER`
  (for example `x-forwarded-for`) names the header whose last entry is the client address. The Azure
  template sets it.
- **Pending devices have their own budget.** Frames from an org's pending devices use a separate
  bucket (`KITH_RELAY_PENDING_FRAMES_PER_SEC`, 10), not the org's.
- **Bounded relay state.** An announce names at most 64 orgs (else `too-many-orgs`), and a device is
  in at most 64 orgs at a time. Rate buckets of an org are dropped once none of its devices is
  online. The relay keeps at most 200,000 revoked devices in total; further notices are refused
  and logged. Operators who serve only approved orgs (REQ-RELAY-008) stay well clear of it.
  Notices per announce (256) count across all its orgs.
- **Signatures outside the lock.** Auth signatures, membership proofs and revocation notices are
  checked before the relay's state is locked; an announce is checked on the blocking thread pool.
  Revocation state is still checked under the lock.

## Consequences

- Memory per connection and per org is bounded by configuration.
- A device that reads too slowly misses frames or is disconnected, then catches up by sync.
- Announces of different connections are no longer applied strictly in arrival order.
- Behind a proxy that does not set the configured header, all clients count as the proxy's address;
  raise or disable (`0`) the per-address limit there.
