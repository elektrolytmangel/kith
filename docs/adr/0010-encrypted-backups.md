# 0010: Encrypted backups without MLS state

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-DATA-006

## Context

If every device of a member (or of the org) is lost, its data and identity are
gone: the relay stores nothing. The user asked for encrypted backups as part of
phase 8. A device's state is its key, its changes and file chunks, its org state
(certificates, root key, open invites) and its MLS state.

## Decision

- `export_backup(passphrase)` writes one file: magic `kith-backup/v1`, a random
  salt and nonce, and XChaCha20-Poly1305 ciphertext under a key derived with
  **Argon2id** (64 MiB, 3 passes). The plaintext holds the device key, all changes,
  the chunks of stored files and the org state.
- **The MLS state is not in the backup.** A snapshot of MLS ratchets is only safe if
  it is never used after the original device sent more messages; restoring it would
  reuse encryption keys (key and nonce reuse). A restored device instead starts
  with no groups and asks an online member to **re-add** it (the REQ-ENC-004 path)
  the first time it sees presence: fresh keys, then catch-up of whatever is newer
  than the backup.
- `import_backup(backup, passphrase, store)` verifies every change and chunk while
  restoring.
- The always-on client exports and restores data directories
  (`--export-backup`, `--restore-backup ... --relay URL`, passphrase in
  `KITH_BACKUP_PASSPHRASE_FILE`, or `KITH_BACKUP_PASSPHRASE`). It holds everything,
  so its backup is the org's.

## Consequences

- Losing all devices no longer loses the org, as long as a backup and its passphrase
  exist and one member (or the always-on client) is online to re-add the restored
  device.
- Restoring while the original device is still in use makes the two re-add each
  other in turn. Restore only when the original is gone.
- A backup contains the device key and the org root key (for the creator): it is as
  sensitive as the device.
- If no other member exists anymore, the restored device has its data but cannot
  rejoin the MLS group. A fresh org is the way out (not automated).

## Alternatives considered

- **Back up the MLS state too**: instant rejoin, but unsafe as above.
- **Per-org data export only (no identity)**: safer, but the restored device would
  need a new invite and would lose its admin role and root key.
