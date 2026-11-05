# 0015: Root-signed policy genesis, named members, stricter restrictions

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-PERM-001, REQ-PERM-002, REQ-PERM-004
- **Amends:** [ADR 0006](0006-policy-object-roles-revocation.md)

## Context

ADR 0006 trusted any `Genesis` that carries a root-signed admin certificate, gave every device the
policy does not name the editor role, ordered a restricted admin's concurrent policy changes only by
seniority, and let any admin lift a restriction. Every admin holds a root-signed admin certificate,
and a device ID alone says nothing about membership, so these rules gave admins and non-members more
than their role.

## Decision

- **Genesis signed by the root key.** The genesis change's author must be the org ID (the root key),
  and its certificate names the creator. `Policy::fold` applies it first, whatever its parents; any
  other genesis is ignored. If the root signed several, the lowest change ID wins.
- **Members are named.** Only devices with an explicit role, or linked to such a device, have a role.
  An admin's `accept_claim` adds `SetRole { editor }` for the new device (one more broadcast frame).
  Devices the policy does not name can't write. Without any policy (e.g. a device that has not caught
  up yet) nothing changes: everyone is an editor until it arrives.
- **Revocation wins for policy changes too.** When a `Restrict` takes admin rights from a device, its
  policy changes that are neither ancestors nor descendants of that `Restrict` don't count, even if
  the causal order would apply them first. `fold` repeats without them until nothing changes.
- **Restrict only lowers.** A `Restrict` whose role is not below the device's current role does not
  count (raising goes through `SetRole`, which needs the root's certificate for admins).
- **Seniority to lift a restriction.** The policy remembers who restricted a device. Raising its role
  again needs the creator or an admin at least as senior.
- **Fewer stored policy changes.** Once a device has an org's policy, it does not store policy changes
  by non-admins (except `LinkDevice` by members), so they don't trigger a re-fold. One that arrived
  too early comes again with the next catch-up.
- **Upgrade.** On start, a device that holds the org root key and finds a policy without a valid
  genesis adds the root-signed genesis and names the current group members as editors. Until then,
  devices of such an org enforce no policy, as before a policy arrives.

## Consequences

- An admin cannot claim to be the creator, and a revoked admin's late policy changes don't count.
- Admitting a device costs one more policy change. Apps send all frames `accept_claim` returns.
- Orgs created by older versions need the root key holder to start the new version once.

## Alternatives considered

- **A special "creator" certificate:** changes the certificate format; the root signature on the
  genesis change says the same.
- **Membership from the MLS group:** group state differs between devices for a while, so the verdict
  would depend on the device.
