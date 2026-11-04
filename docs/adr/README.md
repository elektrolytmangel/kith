# Architecture decision records

One file per decision: `NNNN-short-title.md`, copied from [0000-template.md](0000-template.md).
ADRs are never edited after acceptance. To change a decision, write a new ADR
that supersedes the old one.

Open questions from the design doc that are waiting for an ADR:

- [x] Automerge for all types vs. detect-and-resolve (REQ-DATA-004): [ADR 0003](0003-merge-automerge-default-pluggable.md)
- [x] MLS implementation, ciphersuite, KeyPackage distribution (REQ-ENC-001..004): [ADR 0004](0004-mls-openmls-rustcrypto.md)
- [ ] Ordering of concurrent MLS commits (REQ-ENC-001, see ADR 0004)
- [ ] 30 s relay buffer vs. "no persistence" (REQ-RELAY-005)
- [ ] Push token persistence (REQ-RELAY-007)
- [ ] Rule for changes concurrent with a revocation (REQ-PERM-004)
- [ ] Always-on client required or optional
- [ ] Root key recovery
- [ ] Compaction policy (REQ-DATA-005)
- [ ] Membership proof privacy (REQ-RELAY-004)
