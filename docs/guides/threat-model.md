# Threat model and known limits

What kith protects, against whom, and what it does not. Read it before you put real data in.
**Status: alpha.** The design was reviewed internally and externally in 2026-11 and the findings
fixed (nine security advisories, published); there is **no independent audit** yet. Nothing here
is a guarantee.

## What is protected

| Asset | Protection |
| --- | --- |
| Content of changes and files | End-to-end encrypted: MLS (RFC 9420), one group per organization (and per read-restricted subgroup). Files in 256 KiB encrypted chunks with a key per file. |
| Authorship and integrity | Every change is signed by the device key and hash-linked to its parents; peers verify before storing. |
| Who may write | A signed policy object (admins, roles, per-type write rules), enforced by every device, not by the relay. |
| Who may join | Invites are single use, expire, and are confirmed by comparing a short code on both screens; admins hold certificates the relay checks. |
| Device keys | Web: encrypted at rest under a non-extractable key. Native: the OS keychain or an owner-only file. Org and group state in the store is sealed (ADR 0021). |
| Backups | Passphrase-encrypted (Argon2id + XChaCha20-Poly1305). |

## Who we assume

- **The relay operator is honest but curious, or compromised.** It cannot read or forge content.
- **Members are not all trusted equally.** A member can only do what the policy allows; admins can
  change the policy and remove devices.
- **Devices can be lost or stolen.** Removal stops future reads; it cannot take back what was received.
- **The network is hostile.** Use TLS (`wss://`); the native client refuses plain `ws://` to other hosts.

## What the relay sees

Org IDs, device IDs, who is online and when, message sizes and timing, and the certificate
chains devices announce (including whether a device is an admin). It does **not** see content or
the policy. It stores nothing on disk by default; the optional Azure state holds the approved-org
list and, if you turn it on, the IDs of removed devices.

A malicious relay can **drop or delay messages**, refuse service, and show a device a partial
picture of who is online. It cannot make a device accept a forged change or a stranger as a member
(signatures, certificates, short-code check). Padding against traffic analysis is not done.

## Out of scope / not protected

- **A compromised device or app.** Whoever runs code in your page (XSS) can use the device key and
  read the data like your app does. Use a strict CSP ([web guide](web-production.md#content-security-policy)).
- **A malicious admin.** Admins can remove members and change roles. The org root key holder can
  remove admins at the relay; there is no recovery if every admin is lost.
- **A removed member's earlier data.** They keep everything they received before removal.
- **Metadata** (above), and **denial of service** beyond the relay's rate limits and size caps.
- **Quantum adversaries.** The MLS suite (X25519, Ed25519, ChaCha20-Poly1305) is classical.

## Known limits (state of alpha)

| Limit | Effect | What to do |
| --- | --- | --- |
| **No independent audit** | Unknown flaws may remain | Trials only with users who accept alpha risk |
| **History grows until an admin compacts it** (REQ-DATA-005) | The web store keeps all history in memory; compaction is off by default and trusts admins (a snapshot cannot be checked once its changes are deleted) | Set retention per type, `compact()` regularly; few ten thousand changes per device otherwise |
| **Formats may break between alphas** | Stored data or protocol may stop working after an update | Backup; read *Upgrading*; a promise starts at the first beta (ADR 0012) |
| **Sync needs another member online** | A returning device with nobody online gets nothing | Run the always-on client |
| **Relay revocation memory is RAM** (default) | After a relay restart a removed device can connect again until an admin or the always-on client repeats the notice (ADR 0013, 0024) | Optional persistence (ADR 0014); restart relays rarely |
| **Mobile SDKs are non-production** | Swift/Kotlin live sync never ran on real devices | Ship web |
| **Concurrent admin changes can fork the group** (ADR 0004) | A device added by the losing side needs a new invite | Rare; one admin at a time |
| **Own devices cannot add devices** (ADR 0011) | A member's second device can't invite a third | Link from the original device |
| **Restoring a backup while the original runs** | The two re-add each other | Restore only when the original is gone (ADR 0010) |
| **Subgroup changes need the owner online** (ADR 0008) | Ownership cannot move | Plan who owns a subgroup |
| **Safari evicts storage after 7 days** | A device and its keys can vanish | `requestPersistentStorage()`, backups |

Report vulnerabilities privately through GitHub's private vulnerability reporting (the repository's *Security* tab).
