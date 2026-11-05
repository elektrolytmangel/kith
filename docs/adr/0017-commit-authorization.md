# 0017: Who may change a group's members

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-ENC-001, REQ-ENC-002, REQ-ENC-004, REQ-PERM-002
- **Amends:** [ADR 0004](0004-mls-openmls-rustcrypto.md)

## Context

MLS checks that a commit comes from a group member, not whether that member may add or remove
devices. Roles live in the policy (ADR 0006, ADR 0015), so the client has to apply them to commits.

## Decision

- `Groups::apply_commit_checked` processes a commit for our epoch and, before merging it, refuses it
  if its sender is not the device the relay names, if it carries proposals other than add and remove
  (re-add is both) or proposals by other members, if an added leaf breaks the identity rule
  (credential = signature key = device ID), or if the committer's own new leaf has another identity.
  The caller then checks what it changes (`CommitInfo`: committer, added, removed).
- The client, once it has the org's policy:
  - **org group:** the committer must have a role; admins add and remove; a member may add a device
    linked to it (ADR 0011); any member may re-add a device that is already in the group (a lost
    fork or gap, REQ-ENC-004); revoked devices are never added;
  - **subgroup:** only its owner adds, re-adds or removes, and only devices the policy lists.
  - Key updates are always allowed.
- `accept_claim` sends the policy change naming or linking the new device before the commit, so
  members know it when they check the commit.
- A device answers commit requests, takes commit batches, and acts on a fork only for devices in its
  view of the group that the policy does not exclude. A re-add request is checked to be for the
  sender's own KeyPackage before the group changes.

## Consequences

- A member cannot add outsiders or remove others; only admins and subgroup owners change members.
- A commit checked against a policy that is behind (e.g. a fresh admin grant not received yet) is
  refused; the device then falls behind and fetches the commit again later, when it may pass.
- A fork claim for an epoch we already left cannot be verified (its state is gone); requiring a
  trusted peer and the Welcome checks of ADR 0016 limit it to an extra re-add.
