# Architecture decision records

One file per decision: `NNNN-short-title.md`, copied from [0000-template.md](0000-template.md).
ADRs are never edited after acceptance. To change a decision, write a new ADR
that supersedes the old one.

Open questions from the design doc that are waiting for an ADR:

- [x] Automerge for all types vs. detect-and-resolve (REQ-DATA-004): [ADR 0003](0003-merge-automerge-default-pluggable.md)
- [x] MLS implementation, ciphersuite, KeyPackage distribution (REQ-ENC-001..004): [ADR 0004](0004-mls-openmls-rustcrypto.md)
- [x] Ordering of concurrent MLS commits (REQ-ENC-001): fork resolution in [ADR 0004](0004-mls-openmls-rustcrypto.md)
- [x] Relay-level revocation (REQ-INV-004): [ADR 0013](0013-relay-revocation.md)
- [x] Users with several devices (REQ-ID-002): [ADR 0011](0011-own-devices.md)
- [x] Encrypted backups (REQ-DATA-006): [ADR 0010](0010-encrypted-backups.md)
- [x] Encrypted files (REQ-FILE-001/002): [ADR 0009](0009-encrypted-files.md)
- [x] Read-restricted subgroups (REQ-PERM-003): [ADR 0008](0008-subgroups.md)
- [x] Scope in the change envelope (REQ-PERM-003): [ADR 0007](0007-scope-in-change-envelope.md)
- [x] Org identity, membership proofs, invitations (REQ-ID-003, REQ-INV-*, REQ-RELAY-004): [ADR 0005](0005-org-root-key-certificates-invites.md)
- [x] 30 s relay buffer vs. "no persistence" (REQ-RELAY-005): no buffer (user, 2026-11-04); always-on client instead
- [x] Relay revocation persistence: optional, [ADR 0014](0014-optional-revocation-persistence.md)
- [x] Policy genesis and members named in the policy: [ADR 0015](0015-policy-genesis-and-named-members.md)
- [x] Which Welcomes a device accepts: [ADR 0016](0016-welcome-checks.md)
- [x] Who may change a group's members: [ADR 0017](0017-commit-authorization.md)
- [x] Relay revocation rules and the claim channel: [ADR 0018](0018-relay-revocation-rules.md)
- [x] Relay resource limits: [ADR 0019](0019-relay-resource-limits.md)
- [x] Checked Automerge changes: [ADR 0020](0020-checked-automerge-changes.md)
- [x] Encrypted secrets in the store: [ADR 0021](0021-sealed-stored-secrets.md)
- [x] Invite admission, certificate updates, secret hygiene: [ADR 0022](0022-admission-and-secret-hygiene.md)
- [x] Short codes with the admin's nonce, one sync peer, native TLS: [ADR 0023](0023-claim-nonce-sync-peer-native-tls.md)
- [x] Sharing revocation notices with other admins and the always-on client: [ADR 0024](0024-shared-revocation-notices.md)
- [x] Batched sync rounds, resumable large syncs: [ADR 0025](0025-batched-sync-rounds.md)
- [ ] Push token persistence (REQ-RELAY-007)
- [x] Rule for changes concurrent with a revocation (REQ-PERM-004): [ADR 0006](0006-policy-object-roles-revocation.md)
- [ ] Always-on client required or optional
- [ ] Root key recovery
- [ ] Compaction policy (REQ-DATA-005)
- [ ] Membership proof privacy (REQ-RELAY-004): certificates reveal org and device IDs to the relay (ADR 0005)
