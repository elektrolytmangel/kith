# 0021: Encrypted secrets in the store

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-STORE-003, REQ-STORE-001, REQ-SYNC-006
- **Amends:** [ADR 0012](0012-format-stability.md) (new format marker)

## Context

The client keeps two secrets in its store's meta slots: the org state (it can hold the org
root key) and the MLS group state (the group keys). Stores are plain files or databases: a
SQLite file, IndexedDB, an app's data directory. They end up in backups of a device or a
browser profile, and a native file got the default permissions. The device key is kept
separately and is protected per platform (non-extractable `CryptoKey` on the web, the OS
keychain in apps, a mode 0600 file for the always-on client).

## Decision

- **Sealed meta values.** The client encrypts the org and MLS state with XChaCha20-Poly1305
  before it writes them (`kith_crypto::sealed`). The value starts with `kith/sealed/v1\0`,
  then a random 24-byte nonce; the slot name is authenticated with it, so a value can't be
  moved to another slot. Revocation notices (public) stay unencrypted.
- **Key from the device key.** The storage key is SHA-256 over a domain tag and the device's
  Ed25519 signature of `kith/storage-key/v1\0 || device ID`. Ed25519 signatures are
  deterministic (RFC 8032), so this works for any `Signer`, also one that never reveals its
  secret. The client signs twice when it starts and refuses a signer whose signatures differ.
  The message is domain-separated from every other kith and MLS signature.
- **Older stores are refused.** A store whose meta values are not sealed (written by an
  earlier alpha) is refused with `ClientError::StoredState`, per ADR 0012 rule 4. Restoring
  a backup writes sealed values.
- **Native files owner-only.** `SqliteStore::open` creates the database file with mode 0600
  and removes group and other access from an existing one and its WAL files (Unix). The
  always-on client creates its data directory with mode 0700 and its device key with mode
  0600 in the same call that creates the file.
- **Always-on secrets stay out of logs, arguments and the environment.** Received changes are
  logged by ID only; `--join -` reads the invite link from stdin; the backup passphrase can
  come from a file (`KITH_BACKUP_PASSPHRASE_FILE`), and the argument and variable forms log a
  warning.

## Consequences

- A copy of the store alone reveals no key; together with the device key it reveals everything.
- Application data (changes, file chunks) is stored as before; protect it with the
  platform's disk or app-sandbox encryption.
- Stores from earlier alphas can't be opened: export a backup with the earlier version
  first and restore it, or invite the device again.
- Windows keeps the default ACLs of the user's profile.
