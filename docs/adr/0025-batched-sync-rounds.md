# 0025: Batched sync rounds

- **Status:** accepted
- **Date:** 2026-11-06
- **Requirements:** REQ-SYNC-005

## Context

After reconciliation (Negentropy) a device sent every change the peer lacked, and asked for every
change it lacked, in one burst. A large first sync hit the relay's rate limits (frames and bytes per
second, ADR 0019) and a dropped frame left a hole until the next catch-up.

## Decision

- **One round moves a batch:** at most 500 changes and about 2 MiB in each direction. Changes are
  sent oldest first; a requester asks for the first 500 IDs of its list.
- **New inner message `More` (kind 10, empty):** "reconcile with me again". It is sent after a
  round that was cut: by the side that cut its own offer, and by the side that answered a request
  which hit the limit or was cut itself. The receiver starts a new reconciliation directly with
  the sender, unless one is already running for that scope.
- **Resuming is the same as starting:** what is stored is not asked for again, so an interrupted sync
  (connection lost, rate-limited frames) continues with the next `catchUp`, which finds a smaller
  difference. No extra state is kept.
- Each round takes a few relay frames per batch, so a large sync is paced by the round trips.

## Consequences

- Sync traffic stays bounded per round; the difference shrinks every round or the sync stops.
- A peer that sends `More` repeatedly only makes us start reconciliations, which cost about as much as
  answering one.
- Old clients reject `More` as an unknown message and sync as before, in one burst.
- Not done: direct peer-to-peer transfer (WebRTC), which REQ-SYNC-005 mentions as a preference.
