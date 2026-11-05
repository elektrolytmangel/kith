# 0022: Invite admission, certificate updates and secret hygiene

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-INV-002, REQ-DATA-001, REQ-RELAY-001
- **Amends:** [ADR 0005](0005-org-root-key-certificates-invites.md)

## Context

Several small rules were checked in one place but not in another: an invite was checked
when the claim arrived but not when the admin admitted the device, a certificate sent to
us replaced ours whatever its age, and a few helpers were looser than they needed to be.

## Decision

- **Invites at admission.** `accept_claim` looks the invite up again: it must still exist
  (one invite admits one device) and must not have expired. Accepting a claim drops the
  other pending claims on the same invite.
- **Certificate updates.** An `Outer::Cert` replaces our certificate only if it makes us an
  admin where we were not, or if it was issued later than ours. A replayed older one is
  refused, so it can't take admin rights away.
- **Strict signatures.** Ed25519 signatures of changes, relay authentication, certificates,
  revocations and policy operations are checked with `verify_strict`, which refuses
  small-order keys and non-canonical signatures.
- **Relay errors** don't echo the client's frame.
- **Locks.** The relay and the Swift/Kotlin handle take a lock even after a panic in an
  earlier holder (`PoisonError::into_inner`) instead of failing every later call.
- **Secrets in memory.** Org root keys (dropped org state) and the backup key and contents
  are wiped when dropped (`zeroize`). The device key's `SigningKey` already does this.

## Consequences

- An invite that two devices claimed admits only the first device accepted.
- A device whose certificate is older than the one it holds keeps the newer one.
- Copies of secrets the platform makes (strings, FFI buffers) are not wiped.
