# 0018: Relay revocation rules and the claim channel

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-INV-004, REQ-RELAY-004, REQ-INV-002
- **Amends:** [ADR 0013](0013-relay-revocation.md), [ADR 0014](0014-optional-revocation-persistence.md)

## Context

ADR 0013 accepts any notice signed by a device with a root-made admin certificate, from any announce
with a proof, before checking the announcer. Admins could remove each other, an admin already removed
could still remove others, and a device without a proof (pending) was not checked against the removed
devices. Claims from pending devices arrived as ordinary deliveries. Org IDs were compared as sent.

## Decision

- **Announcer first.** The relay checks the announcer's proof before reading its notices, and only
  an admin's announce may carry notices; then it checks the announcer again (a notice may name it).
- **Admins are removed by the root only.** A notice may be signed by the org root key
  (`Revocation::issue_by_root`, no chain). When the relay checks a certificate chain, a notice
  against an admin's certificate counts only if the root signed it; notices against members count
  from any admin. The client signs its notices with the root key whenever it holds it.
- **A removed admin revokes nobody.** A notice whose issuer the root removed is refused. Stored
  notices (ADR 0014) are loaded root-signed first; an admin's stored notice then still counts if it
  is older than the root's notice removing that admin (issuer clocks).
- **Pending is not a way back.** A device named in a notice can't announce without a proof either.
- **Claims have their own frame.** `invite-claim` reaches its targets as `claim-deliver`. Clients take
  only an invite claim from it, and an invite claim only from it.
- **One spelling per org.** The relay turns every org ID into lower-case hex and refuses frames whose
  org ID is not a hex key (`bad-org`).

## Consequences

- An admin can no longer lock out other admins, and a removed admin's notices are ignored.
- Removing an admin at the relay needs the device that holds the org root key. The policy (ADR 0006,
  0015) still revokes admins removed by a more senior admin; the relay keeps admitting them until the
  root holder removes them.
- New frame type: older clients ignore claims (no users yet).
