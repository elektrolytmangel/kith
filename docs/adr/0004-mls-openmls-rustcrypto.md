# 0004: MLS with OpenMLS, one ciphersuite, sans-IO groups

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-ENC-001..004 (also REQ-ID-001, REQ-INV-*)

## Context

Relay frame bodies are plaintext until phase 4, so the relay operator can read
all data. The design doc chose MLS (RFC 9420), one group per organization, but
left open the implementation, the ciphersuite, how KeyPackages travel, how the
first group is created, and what happens to existing plaintext data.

## Decision

- **OpenMLS 0.9** with the **RustCrypto** provider (`openmls_rust_crypto`).
  Pure Rust, so it builds for wasm32, iOS and Android without C toolchains. On
  wasm32 the `openmls/js` feature provides browser randomness and clock.
- **One ciphersuite:** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.
  Its signature scheme is Ed25519, so the **device key is the MLS signature key**
  and the credential is the device ID (a `BasicCredential` whose identity must
  equal the signature key; KeyPackages that break this are refused). Any kith
  `Signer` (keychain, enclave) signs MLS messages; RFC 9420 signature labels keep
  them distinct from kith change and relay-auth signatures.
- **Group ID = org ID.** `kith_crypto::Groups` holds all of a device's groups,
  its unused KeyPackages and a commit log of the last 256 commits per group,
  saved as one blob (`to_bytes`/`from_bytes`, it contains secrets).
- **All messages are `PrivateMessage`s**, commits included
  (`PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`). The relay sees group ID, epoch, content
  type, sizes and timing, not content or membership changes.
- **KeyPackages go `direct` to an online admin.** The relay stays stateless; both
  devices must be online to add a device (user decision; phase 5 wraps this in
  invitations).
- **Until phase 5:** the creator calls `create_group` and adds devices with
  `add_member(key_package)` → commit (broadcast) + Welcome (direct).
- **Missed commits** (REQ-ENC-002): a message for a later epoch is reported as
  `EpochGap`; the device fetches `commits_since(epoch)` from a peer and applies
  them in order. **Too far behind** (REQ-ENC-004): a member replaces the device's
  old leaf with a fresh KeyPackage (`readd_member`, one commit + Welcome).
- Up to 3 past epochs' keys are kept so messages that cross a commit in flight
  still decrypt.
- **Hard break:** once the client uses MLS, plaintext bodies are rejected. No
  migration of existing plaintext data (alpha).
- The workspace **MSRV is 1.91**, because `openmls` 0.9 requires it.

## Consequences

- The relay operator can no longer read data, only metadata (accepted non-goal).
- **Concurrent commits fork the group.** The relay does not order messages, so if
  two members commit in the same epoch, each merges its own commit and refuses the
  other's. Mitigation for now: commits are rare (adds, removals, key rotation) and
  the re-add path recovers a device. A deterministic tie-break or an ordering
  device (the always-on client, phase 7) is open.
- A device must be online to be added, and an admin must be online too.
- Old clients and plaintext data stop working with the new wire format.

## Alternatives considered

- **libcrux provider**: faster, formally verified parts, but larger and with less
  proven wasm/mobile support at the time; can be swapped in behind `Groups`.
- **AES-GCM suite** (the RFC's mandatory suite): fast with AES hardware, slower on
  wasm; ChaCha20 is constant-time everywhere.
- **Post-quantum hybrid suite**: large KeyPackages, still experimental in OpenMLS.
- **KeyPackage directory in relay RAM**: lets admins add offline devices, but gives
  the relay state that a restart loses.
- **Own Signal-style sender keys**: no standard, no post-compromise security.
