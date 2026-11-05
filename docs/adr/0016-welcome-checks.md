# 0016: Which Welcomes a device accepts

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-ENC-001, REQ-ENC-004, REQ-INV-002
- **Amends:** [ADR 0004](0004-mls-openmls-rustcrypto.md) (re-add), [ADR 0005](0005-org-root-key-certificates-invites.md) (joining)

## Context

A Welcome from MLS proves that its sender built a group containing one of our KeyPackages. It says
nothing about whether that group is the org's real group or whether we asked to join it. Joining
replaces the state we had for the group (needed after a lost fork or a restore).

## Decision

Before joining, `Groups::join_checked` hands the verified Welcome's group, adder and members to the
client, which accepts it only if one of these holds:

- **We asked for it.** We sent a KeyPackage for this group to this device (re-add after a fork or a
  gap, rejoin after a restore, subgroup membership). The adder must be that device. For the org's
  group, every member must have a role in the policy or already be in our group (and not be
  revoked). For a subgroup, the adder must be its owner and every member listed in the policy.
- **First join.** We have neither a group nor a certificate for the org, and the Welcome brings a
  certificate chain that proves us under the org root key and was issued by the adder. For an
  own-device invite we claimed in this session, the adder must also be the invite's issuer.

The relay's `from` must match the adder. Everything else is rejected and changes nothing.

A device only answers "re-add needed" from a device that is in its view of that group and not
excluded by the policy.

## Consequences

- Nobody can move a device into a group it did not ask for, or add devices we don't know to it.
- Requests are remembered in RAM: a Welcome that arrives after a restart is rejected, and the device
  asks again (the existing retries for re-add, rejoin and subgroups).

## Alternatives considered

- **Persist pending requests:** more state on disk for a rare case the retries already cover.
