# 0023: Short codes with the admin's nonce, one sync peer, native TLS

- **Status:** accepted
- **Date:** 2026-11-06
- **Requirements:** REQ-INV-002, REQ-INV-003, REQ-SYNC-001, REQ-ENC-002, REQ-RELAY-004
- **Amends:** [ADR 0005](0005-org-root-key-certificates-invites.md), [ADR 0022](0022-admission-and-secret-hygiene.md)

## Context

The short code both devices show (REQ-INV-003) was `HMAC(secret, token || H(KeyPackage))`.
It protects a leaked link: a device that claims with the link gets a code the user's
device does not show. But whoever has the link and sees the user's claim (a relay, or
anyone on a plain `ws://` connection) can compute the user's code and try KeyPackages of
its own until one gives the same six digits, about a million tries. It then sends its
claim instead of the user's, and both screens match.

Three smaller gaps were in the same area of the client and the native network crate:
any member could answer our running catch-up, a message's (unauthenticated) epoch made us
resend our commit log on every message, and `kith-net` accepted `ws://` to any host,
64 MiB messages and, in the release builds, no `wss://` at all (no TLS backend).

## Decision

- **Admin nonce.** The admin answers a valid claim at once with `Outer::ClaimNonce`
  (direct to the pending device): a random 32-byte nonce, its signature over
  `kith/invite-nonce/v1 || org || token || H(KeyPackage) || nonce`, and its certificate
  chain. The code is `HMAC(secret, "kith/invite-code/v2" || token || H(KeyPackage) ||
  nonce)`. The claimer checks the chain against the org ID and the signature, and that
  the signer is an admin (or, for an own-device invite, the invite's issuer); only then
  does it show the code (`Event::ClaimCode`), and from then on only that device's Welcome
  is accepted. A claimer commits to its KeyPackage before the nonce exists, so a second
  claim with the link matches the user's code with probability 10⁻⁶. A repeated claim
  with the same KeyPackage keeps its nonce; at most 8 claims per invite wait at once.
- **API.** `claim_invite` / `claimInvite` / `RelaySession.claim` no longer return a code;
  it arrives as `ClaimCode` (`claimCode` on the web, `.claimCode` in Swift). A breaking
  change, accepted for the alpha.
- **One sync peer.** A reconciliation runs with one peer: the device we sent it to
  directly, or the first that answers a `SyncRequest`. Answers from other devices are
  ignored.
- **Unasked commits.** Commits for a sender at an older epoch go out only if the sender is
  a member of that group, and once per (group, sender, our epoch). A device that still
  lacks them asks with `CommitRequest`.
- **Native TLS.** `kith-net` has TLS on by default (rustls with the ring provider and the
  webpki roots), accepts `ws://` only for this machine (`localhost`, `127.0.0.0/8`,
  `::1`) and messages up to 16 MiB.

## Consequences

- One more message per claim; the code appears on the new device a round trip later.
- Old and new clients can't admit each other (v1 vs v2 codes, no `ClaimNonce`); all
  platforms change together.
- Relays reachable only over plain `ws://` from another host no longer work with the native
  client; put TLS in front (the Compose file and Azure template already do).
