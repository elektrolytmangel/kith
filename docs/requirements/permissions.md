# Permissions

### REQ-PERM-001: Policy object

- **Priority:** must | **Phase:** 6 | **Status:** implemented | **Verify:** test | **Source:** design §Policy object

A policy object, rooted in the organization root key and writable only by
admins, must define members, roles, per-type rules and revocations.

### REQ-PERM-002: Validate every incoming change

- **Priority:** must | **Phase:** 6 | **Status:** implemented | **Verify:** test | **Source:** design §Validation

Clients must validate every incoming change (signature, hash, author
permission under the policy) and must never let an invalid change take effect.
Changes with bad signatures are dropped; signature-valid changes the policy
rejects are quarantined (kept out of history and merging, still forwarded so every
device decides the same, ADR 0006).

### REQ-PERM-003: Read-restricted subgroups

- **Priority:** must | **Phase:** 6 | **Status:** accepted | **Verify:** test | **Source:** design §Restricted read

Data readable by only some members must live in a separate MLS group.

### REQ-PERM-004: Deterministic concurrent permission changes

- **Priority:** must | **Phase:** 6 | **Status:** implemented | **Verify:** test | **Source:** design §Concurrent permission changes

Every client must apply identical rules for changes concurrent with a
revocation and for conflicting admin operations: revocation wins (keep lists),
seniority decides admin conflicts, the root always wins ([ADR 0006](../adr/0006-policy-object-roles-revocation.md)).
