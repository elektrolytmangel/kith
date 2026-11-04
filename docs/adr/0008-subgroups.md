# 0008: Read-restricted subgroups

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-PERM-003

## Context

Some data must be readable by only part of an org (for example `finance`). Read
access in kith is who holds the decryption keys. ADR 0007 already scopes every
change. User decision (2026-11-04): org admins manage subgroups through the
policy, and each subgroup is its own MLS group.

## Decision

- **Policy op `SetSubgroup { name, members, keep }`** (admins only) creates a
  subgroup or replaces its member list. Writes in scope `<org>/<name>` need
  membership plus the usual role. Changes by removed members stay valid only if
  listed in `keep` (the ones the admin had seen), as with revocation (ADR 0006).
- **One MLS group per subgroup**, keyed `<org>/<name>`. The author of the first
  `SetSubgroup` for a name is its **owner**. Only the owner adds and removes devices
  in that MLS group, so subgroup commits never fork. A member that sees itself in
  the policy but not in the group sends the owner a KeyPackage. The owner adds it
  if the policy lists it, and removes devices the policy no longer lists (keys
  rotate).
- **The MLS group is the scope**: a decrypted message's group is the scope of the
  data inside it, so catch-up, offers and live changes work per subgroup with no
  new fields. Subgroup catch-up goes `direct` to the owner, or another member, since
  the relay does not know subgroups. MLS catch-up messages (commit request, commits,
  re-add, KeyPackage) carry their group.
- Subgroup traffic is broadcast to the whole org (the relay routes by org);
  non-members ignore it, since they cannot decrypt it.

## Consequences

- Apps get per-subgroup read access with one call (`createSubgroup`) and a scope on
  creation (`createIn("<org>/<name>", ...)`).
- **Membership changes wait for the owner device** to be online. Moving ownership
  to another device is not supported yet.
- Removed members keep what they already received (accepted, as for the org).
- The relay sees that subgroup traffic exists (sizes, timing), not who is in it.

## Alternatives considered

- **Any member or admin adds to the MLS group**: concurrent adds would fork the
  group. The fork resolution works, but with more churn.
- **Per-subgroup managers**: a second authority to resolve conflicts for (user chose
  admins).
- **Separate relay org per subgroup**: leaks subgroup membership to the relay and
  needs certificates per subgroup.
