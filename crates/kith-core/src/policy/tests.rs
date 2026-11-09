use super::*;
use crate::membership::MembershipCert;
use crate::{ObjectType, Signer, UnsignedChange};
use ed25519_dalek::{Signer as _, SigningKey};

struct K(SigningKey);
impl Signer for K {
    fn device_id(&self) -> DeviceId {
        DeviceId(self.0.verifying_key().to_bytes())
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}
fn key() -> K {
    K(SigningKey::from_bytes(&crate::random_bytes()))
}

struct Org {
    root: K,
    id: DeviceId,
}

impl Org {
    fn new() -> Self {
        let root = key();
        let id = root.device_id();
        Self { root, id }
    }
    fn admin_cert(&self, d: &K) -> MembershipCert {
        MembershipCert::issue(&self.root, self.id, d.device_id(), true, 1)
    }
    fn op(&self, by: &K, parents: Vec<ChangeId>, op: PolicyOp) -> Change {
        Change::sign(
            UnsignedChange {
                scope: crate::Scope::org(&self.id),
                object_id: policy_object_id(&self.id),
                object_type: ObjectType::new(POLICY_TYPE),
                parents,
                timestamp_ms: 1,
                payload: op.encode(),
            },
            by,
        )
    }
}

/// `by` names `who` with `role` (as an admin does when admitting a device).
fn name(org: &Org, by: &K, parent: &Change, who: &K, role: Role) -> Change {
    org.op(
        by,
        vec![parent.change_id],
        PolicyOp::SetRole {
            device: who.device_id(),
            role,
            cert: None,
        },
    )
}

fn data(by: &K, ty: &str) -> Change {
    Change::sign(
        UnsignedChange {
            scope: crate::Scope::local(),
            object_id: ObjectId::random(),
            object_type: ObjectType::new(ty),
            parents: vec![],
            timestamp_ms: 1,
            payload: b"x".to_vec(),
        },
        by,
    )
}

#[test]
fn ops_roundtrip() {
    let org = Org::new();
    let a = key();
    for op in [
        PolicyOp::Genesis {
            admin: org.admin_cert(&a),
        },
        PolicyOp::SetRole {
            device: a.device_id(),
            role: Role::Viewer,
            cert: None,
        },
        PolicyOp::SetRole {
            device: a.device_id(),
            role: Role::Admin,
            cert: Some(org.admin_cert(&a)),
        },
        PolicyOp::SetRule {
            object_type: "config".into(),
            write: Role::Admin,
        },
        PolicyOp::SetRetention {
            object_type: "note".into(),
            retention: Retention::KeepLast(500),
        },
        PolicyOp::SetRetention {
            object_type: "note".into(),
            retention: Retention::KeepDays(90),
        },
        PolicyOp::SetRetention {
            object_type: "note".into(),
            retention: Retention::KeepAll,
        },
        PolicyOp::Restrict {
            device: a.device_id(),
            role: None,
            keep: vec![ChangeId([1; 32]), ChangeId([2; 32])],
        },
        PolicyOp::Restrict {
            device: a.device_id(),
            role: Some(Role::Viewer),
            keep: vec![],
        },
        PolicyOp::LinkDevice {
            device: a.device_id(),
        },
    ] {
        assert_eq!(PolicyOp::decode(&op.encode()).unwrap(), op);
    }
    assert!(PolicyOp::decode(&[]).is_err());
    assert!(PolicyOp::decode(&[9, 0]).is_err());
    assert!(PolicyOp::decode(&[1, 2, 1]).is_err(), "empty object type");
}

/// req: REQ-PERM-001
/// req: REQ-PERM-002
#[test]
fn roles_and_rules_decide_who_writes_what() {
    let org = Org::new();
    let (creator, editor, viewer) = (key(), key(), key());
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let rule = org.op(
        &creator,
        vec![g.change_id],
        PolicyOp::SetRule {
            object_type: "config".into(),
            write: Role::Admin,
        },
    );
    let ed = name(&org, &creator, &rule, &editor, Role::Editor);
    let vw = name(&org, &creator, &ed, &viewer, Role::Editor);
    let demote = org.op(
        &creator,
        vec![vw.change_id],
        PolicyOp::Restrict {
            device: viewer.device_id(),
            role: Some(Role::Viewer),
            keep: vec![],
        },
    );
    let p = Policy::fold(
        &org.id,
        &[
            demote.clone(),
            g.clone(),
            vw.clone(),
            rule.clone(),
            ed.clone(),
        ],
    );
    assert_eq!(p.accepted.len(), 5);
    // Devices the policy does not name have no role.
    assert_eq!(p.role_of(&key().device_id()), None);
    assert!(!p.allows(&data(&key(), "note")));
    assert!(p.allows(&data(&editor, "note")));
    assert!(!p.allows(&data(&editor, "config")));
    assert!(p.allows(&data(&creator, "config")));
    assert!(!p.allows(&data(&viewer, "note")));
    // Non-admins cannot change the policy.
    let sneaky = org.op(
        &editor,
        vec![demote.change_id],
        PolicyOp::SetRule {
            object_type: "note".into(),
            write: Role::Viewer,
        },
    );
    let p2 = Policy::fold(
        &org.id,
        &[
            g.clone(),
            rule.clone(),
            ed,
            vw,
            demote.clone(),
            sneaky.clone(),
        ],
    );
    assert!(!p2.accepted.contains(&sneaky.change_id));
    assert_eq!(p2.write_rule("note"), Role::Editor);
    // A genesis by someone without the root's admin certificate does nothing.
    let fake = org.op(
        &editor,
        vec![],
        PolicyOp::Genesis {
            admin: MembershipCert::issue(&editor, org.id, editor.device_id(), true, 1),
        },
    );
    assert!(Policy::fold(&org.id, &[fake]).creator.is_none());
    // Nor does one with a root-signed admin certificate, unless the root signed
    // the change itself.
    let not_root = org.op(
        &editor,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&editor),
        },
    );
    assert!(
        Policy::fold(&org.id, std::slice::from_ref(&not_root))
            .creator
            .is_none()
    );
    assert_eq!(
        Policy::fold(&org.id, &[g.clone(), not_root]).creator,
        Some(creator.device_id())
    );
}

/// req: REQ-PERM-004
#[test]
fn revocation_keeps_only_what_the_admin_had_seen() {
    let org = Org::new();
    let (creator, bob) = (key(), key());
    let seen = data(&bob, "note");
    let offline = data(&bob, "note");
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let revoke = org.op(
        &creator,
        vec![g.change_id],
        PolicyOp::Restrict {
            device: bob.device_id(),
            role: None,
            keep: vec![seen.change_id],
        },
    );
    let p = Policy::fold(&org.id, &[g, revoke]);
    assert_eq!(p.role_of(&bob.device_id()), None);
    assert!(p.allows(&seen));
    assert!(!p.allows(&offline), "made concurrently with the revocation");
    assert!(!p.allows(&data(&bob, "note")));
}

/// req: REQ-PERM-004
#[test]
fn concurrent_admin_conflicts_resolve_the_same_everywhere() {
    let org = Org::new();
    let (creator, a1, a2) = (key(), key(), key());
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let mk1 = org.op(
        &creator,
        vec![g.change_id],
        PolicyOp::SetRole {
            device: a1.device_id(),
            role: Role::Admin,
            cert: Some(org.admin_cert(&a1)),
        },
    );
    let mk2 = org.op(
        &creator,
        vec![mk1.change_id],
        PolicyOp::SetRole {
            device: a2.device_id(),
            role: Role::Admin,
            cert: Some(org.admin_cert(&a2)),
        },
    );
    // a1 and a2 revoke each other at the same time; a1 is senior.
    let r1 = org.op(
        &a1,
        vec![mk2.change_id],
        PolicyOp::Restrict {
            device: a2.device_id(),
            role: None,
            keep: vec![],
        },
    );
    let r2 = org.op(
        &a2,
        vec![mk2.change_id],
        PolicyOp::Restrict {
            device: a1.device_id(),
            role: None,
            keep: vec![],
        },
    );
    // Nobody restricts the creator.
    let r3 = org.op(
        &a1,
        vec![mk2.change_id],
        PolicyOp::Restrict {
            device: creator.device_id(),
            role: None,
            keep: vec![],
        },
    );
    let all = [g, mk1, mk2, r1.clone(), r2.clone(), r3.clone()];
    let p = Policy::fold(&org.id, &all);
    assert!(p.accepted.contains(&r1.change_id));
    assert!(!p.accepted.contains(&r2.change_id));
    assert!(!p.accepted.contains(&r3.change_id));
    assert_eq!(p.role_of(&a1.device_id()), Some(Role::Admin));
    assert_eq!(p.role_of(&a2.device_id()), None);
    assert_eq!(p.role_of(&creator.device_id()), Some(Role::Admin));
    // Same result in any order.
    let mut rev = all.to_vec();
    rev.reverse();
    assert_eq!(Policy::fold(&org.id, &rev), p);
    // An admin needs the root's certificate.
    let x = key();
    let bad = org.op(
        &creator,
        vec![],
        PolicyOp::SetRole {
            device: x.device_id(),
            role: Role::Admin,
            cert: Some(MembershipCert::issue(
                &creator,
                org.id,
                x.device_id(),
                true,
                1,
            )),
        },
    );
    let mut with_bad = all.to_vec();
    with_bad.push(bad.clone());
    assert!(
        !Policy::fold(&org.id, &with_bad)
            .accepted
            .contains(&bad.change_id)
    );
}

/// req: REQ-PERM-003
#[test]
fn subgroups_limit_writes_to_their_members() {
    let org = Org::new();
    let (creator, alice, bob) = (key(), key(), key());
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let make = PolicyOp::SetSubgroup {
        name: "finance".into(),
        members: vec![creator.device_id(), alice.device_id()],
        keep: vec![],
    };
    assert_eq!(PolicyOp::decode(&make.encode()).unwrap(), make);
    let al = name(&org, &creator, &g, &alice, Role::Editor);
    let sg = org.op(&creator, vec![al.change_id], make);
    let in_sub = |by: &K| {
        Change::sign(
            UnsignedChange {
                scope: crate::Scope::subgroup(&org.id, "finance").unwrap(),
                object_id: ObjectId::random(),
                object_type: ObjectType::new("ledger"),
                parents: vec![],
                timestamp_ms: 1,
                payload: vec![],
            },
            by,
        )
    };
    let p = Policy::fold(&org.id, &[g.clone(), al.clone(), sg.clone()]);
    assert_eq!(p.subgroup_owners.get("finance"), Some(&creator.device_id()));
    let by_alice = in_sub(&alice);
    assert!(p.allows(&by_alice));
    assert!(!p.allows(&in_sub(&bob)), "not a member");
    // Alice is removed; her change the admin had seen stays.
    let rm = org.op(
        &creator,
        vec![sg.change_id],
        PolicyOp::SetSubgroup {
            name: "finance".into(),
            members: vec![creator.device_id()],
            keep: vec![by_alice.change_id],
        },
    );
    let p = Policy::fold(&org.id, &[g, al, sg, rm]);
    assert!(p.allows(&by_alice));
    assert!(!p.allows(&in_sub(&alice)));
    assert_eq!(p.subgroup("finance").map(|m| m.len()), Some(1));
    assert!(PolicyOp::decode(&[1, 4, 3, b'B', b'a', b'd', 0, 0, 0, 0]).is_err());
}

#[test]
fn policy_ids_differ_per_org() {
    assert_ne!(
        policy_object_id(&Org::new().id),
        policy_object_id(&Org::new().id)
    );
}

/// req: REQ-ID-002
#[test]
fn members_link_their_own_devices() {
    let org = Org::new();
    let (creator, alice, phone, bob, other) = (key(), key(), key(), key(), key());
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let viewer = name(&org, &creator, &g, &alice, Role::Viewer);
    // Alice (a viewer, not an admin) links her phone: same role.
    let link = org.op(
        &alice,
        vec![viewer.change_id],
        PolicyOp::LinkDevice {
            device: phone.device_id(),
        },
    );
    let p = Policy::fold(&org.id, &[g.clone(), viewer.clone(), link.clone()]);
    assert!(p.accepted.contains(&link.change_id));
    assert_eq!(p.role_of(&phone.device_id()), Some(Role::Viewer));
    assert_eq!(p.linked_to(&alice.device_id()), vec![phone.device_id()]);
    assert!(!p.allows(&data(&phone, "note")), "viewer on both devices");
    // Admitting someone else's device, or chaining links, does not count.
    let for_bob = org.op(
        &alice,
        vec![link.change_id],
        PolicyOp::LinkDevice {
            device: bob.device_id(),
        },
    );
    let chained = org.op(
        &phone,
        vec![link.change_id],
        PolicyOp::LinkDevice {
            device: other.device_id(),
        },
    );
    let again = org.op(
        &bob,
        vec![link.change_id],
        PolicyOp::LinkDevice {
            device: phone.device_id(),
        },
    );
    let p2 = Policy::fold(
        &org.id,
        &[
            g.clone(),
            viewer.clone(),
            link.clone(),
            chained.clone(),
            again.clone(),
        ],
    );
    assert!(!p2.accepted.contains(&chained.change_id), "no chains");
    assert!(!p2.accepted.contains(&again.change_id), "already linked");
    assert_eq!(p2.linked_to(&bob.device_id()), vec![]);
    // (Linking `bob` is fine for Alice's policy: it only says "bob is Alice's".)
    let p3 = Policy::fold(
        &org.id,
        &[g.clone(), viewer.clone(), link.clone(), for_bob.clone()],
    );
    assert!(p3.accepted.contains(&for_bob.change_id));
    // An admin's linked device is an editor, never an admin.
    let admin_link = org.op(
        &creator,
        vec![g.change_id],
        PolicyOp::LinkDevice {
            device: other.device_id(),
        },
    );
    let p4 = Policy::fold(&org.id, &[g.clone(), admin_link]);
    assert_eq!(p4.role_of(&other.device_id()), Some(Role::Editor));
    // Revoking Alice, keeping her seen change, takes the phone with her.
    let by_phone = data(&phone, "note");
    let revoke = org.op(
        &creator,
        vec![link.change_id],
        PolicyOp::Restrict {
            device: alice.device_id(),
            role: None,
            keep: vec![by_phone.change_id],
        },
    );
    let p5 = Policy::fold(&org.id, &[g, viewer, link, revoke]);
    assert_eq!(p5.role_of(&phone.device_id()), None);
    assert!(p5.allows(&by_phone), "kept change of the linked device");
    assert!(!p5.allows(&data(&phone, "note")));
    assert!(PolicyOp::decode(&[1, 5, 1, 2]).is_err());
}

fn op_ts(org: &Org, by: &K, parents: Vec<ChangeId>, op: PolicyOp, ts: u64) -> Change {
    Change::sign(
        UnsignedChange {
            scope: crate::Scope::org(&org.id),
            object_id: policy_object_id(&org.id),
            object_type: ObjectType::new(POLICY_TYPE),
            parents,
            timestamp_ms: ts,
            payload: op.encode(),
        },
        by,
    )
}

/// Creator, plus `admin` made an admin by the creator.
fn org_with_admin(org: &Org, creator: &K, admin: &K) -> (Change, Change) {
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(creator),
        },
    );
    let a = org.op(
        creator,
        vec![g.change_id],
        PolicyOp::SetRole {
            device: admin.device_id(),
            role: Role::Admin,
            cert: Some(org.admin_cert(admin)),
        },
    );
    (g, a)
}

/// req: REQ-PERM-004
#[test]
fn only_the_root_signed_genesis_names_the_creator() {
    let org = Org::new();
    let (creator, x) = (key(), key());
    let (g, add) = org_with_admin(&org, &creator, &x);
    let rev = org.op(
        &creator,
        vec![add.change_id],
        PolicyOp::Restrict {
            device: x.device_id(),
            role: None,
            keep: vec![],
        },
    );
    // x (root-certified admin, then revoked) tries rival genesis ops, including
    // ones with a lower change ID than the real one.
    let rivals: Vec<Change> = (0u64..)
        .map(|ts| {
            op_ts(
                &org,
                &x,
                vec![],
                PolicyOp::Genesis {
                    admin: org.admin_cert(&x),
                },
                ts,
            )
        })
        .filter(|c| c.change_id < g.change_id)
        .take(2)
        .collect();
    let mut all = vec![g, add, rev];
    all.extend(rivals.iter().cloned());
    let p = Policy::fold(&org.id, &all);
    assert_eq!(p.creator, Some(creator.device_id()));
    assert_eq!(p.role_of(&creator.device_id()), Some(Role::Admin));
    assert_eq!(p.role_of(&x.device_id()), None);
    assert!(rivals.iter().all(|r| !p.accepted.contains(&r.change_id)));
}

/// req: REQ-PERM-002
#[test]
fn unnamed_devices_cannot_write_or_link_members() {
    let org = Org::new();
    let (creator, member, viewer, stranger) = (key(), key(), key(), key());
    let g = org.op(
        &org.root,
        vec![],
        PolicyOp::Genesis {
            admin: org.admin_cert(&creator),
        },
    );
    let m = name(&org, &creator, &g, &member, Role::Editor);
    let v = name(&org, &creator, &m, &viewer, Role::Viewer);
    let p = Policy::fold(&org.id, &[g.clone(), m.clone(), v.clone()]);
    assert!(!p.allows(&data(&stranger, "note")), "unknown key");
    assert!(p.allows(&data(&member, "note")));
    // Linking a named member's device does not count, and neither does a
    // stranger linking anything.
    let link = org.op(
        &viewer,
        vec![v.change_id],
        PolicyOp::LinkDevice {
            device: member.device_id(),
        },
    );
    let by_stranger = org.op(
        &stranger,
        vec![v.change_id],
        PolicyOp::LinkDevice {
            device: key().device_id(),
        },
    );
    let p = Policy::fold(&org.id, &[g, m, v, link.clone(), by_stranger.clone()]);
    assert!(!p.accepted.contains(&link.change_id));
    assert!(!p.accepted.contains(&by_stranger.change_id));
    assert_eq!(p.role_of(&member.device_id()), Some(Role::Editor));
}

/// req: REQ-PERM-004
#[test]
fn only_a_senior_admin_lifts_a_restriction() {
    let org = Org::new();
    let (creator, junior, bad) = (key(), key(), key());
    let (g, j) = org_with_admin(&org, &creator, &junior);
    let b = name(&org, &creator, &j, &bad, Role::Editor);
    let r = org.op(
        &creator,
        vec![b.change_id],
        PolicyOp::Restrict {
            device: bad.device_id(),
            role: None,
            keep: vec![],
        },
    );
    let base = vec![g, j, b, r.clone()];
    // The junior admin can't undo the creator's revocation, by either op.
    for op in [
        PolicyOp::SetRole {
            device: bad.device_id(),
            role: Role::Editor,
            cert: None,
        },
        PolicyOp::Restrict {
            device: bad.device_id(),
            role: Some(Role::Viewer),
            keep: vec![],
        },
    ] {
        let u = org.op(&junior, vec![r.change_id], op);
        let mut all = base.clone();
        all.push(u.clone());
        let p = Policy::fold(&org.id, &all);
        assert!(!p.accepted.contains(&u.change_id));
        assert_eq!(p.role_of(&bad.device_id()), None);
    }
    // The creator can.
    let u = name(&org, &creator, &r, &bad, Role::Editor);
    let mut all = base;
    all.push(u);
    let p = Policy::fold(&org.id, &all);
    assert_eq!(p.role_of(&bad.device_id()), Some(Role::Editor));
    assert!(!p.restricted_by.contains_key(&bad.device_id()));
}

/// req: REQ-PERM-001
#[test]
fn restrict_never_raises_a_role() {
    let org = Org::new();
    let (creator, admin, member) = (key(), key(), key());
    let (g, a) = org_with_admin(&org, &creator, &admin);
    let m = name(&org, &creator, &a, &member, Role::Editor);
    // An admin can't make an admin without the root's certificate by "restricting".
    let up = org.op(
        &admin,
        vec![m.change_id],
        PolicyOp::Restrict {
            device: member.device_id(),
            role: Some(Role::Admin),
            keep: vec![],
        },
    );
    let p = Policy::fold(&org.id, &[g, a, m, up.clone()]);
    assert!(!p.accepted.contains(&up.change_id));
    assert_eq!(p.role_of(&member.device_id()), Some(Role::Editor));
}

/// req: REQ-PERM-004
#[test]
fn a_revoked_admin_cannot_backdate_policy_changes() {
    let org = Org::new();
    let (creator, x, victim) = (key(), key(), key());
    let (g, add) = org_with_admin(&org, &creator, &x);
    let v = name(&org, &creator, &add, &victim, Role::Editor);
    // The creator revokes x, having seen v.
    let rev = org.op(
        &creator,
        vec![v.change_id],
        PolicyOp::Restrict {
            device: x.device_id(),
            role: None,
            keep: vec![],
        },
    );
    // Later, x writes ops on the old parent v: they are concurrent with the
    // revocation, and the creator never saw them.
    let backdated = org.op(
        &x,
        vec![v.change_id],
        PolicyOp::Restrict {
            device: victim.device_id(),
            role: None,
            keep: vec![],
        },
    );
    let rule = org.op(
        &x,
        vec![backdated.change_id],
        PolicyOp::SetRule {
            object_type: "note".into(),
            write: Role::Admin,
        },
    );
    let all = [g, add, v, rev.clone(), backdated.clone(), rule.clone()];
    let p = Policy::fold(&org.id, &all);
    assert!(p.accepted.contains(&rev.change_id));
    assert!(!p.accepted.contains(&backdated.change_id));
    assert!(!p.accepted.contains(&rule.change_id));
    assert_eq!(p.role_of(&victim.device_id()), Some(Role::Editor));
    assert_eq!(p.write_rule("note"), Role::Editor);
    let mut rev_order = all.to_vec();
    rev_order.reverse();
    assert_eq!(Policy::fold(&org.id, &rev_order), p);
}

/// req: REQ-PERM-004
#[test]
fn an_admin_restored_by_the_creator_acts_again() {
    let org = Org::new();
    let (creator, x) = (key(), key());
    let (g, add) = org_with_admin(&org, &creator, &x);
    let rev = org.op(
        &creator,
        vec![add.change_id],
        PolicyOp::Restrict {
            device: x.device_id(),
            role: None,
            keep: vec![],
        },
    );
    let back = org.op(
        &creator,
        vec![rev.change_id],
        PolicyOp::SetRole {
            device: x.device_id(),
            role: Role::Admin,
            cert: Some(org.admin_cert(&x)),
        },
    );
    let rule = org.op(
        &x,
        vec![back.change_id],
        PolicyOp::SetRule {
            object_type: "note".into(),
            write: Role::Viewer,
        },
    );
    let p = Policy::fold(&org.id, &[g, add, rev, back, rule.clone()]);
    assert!(p.accepted.contains(&rule.change_id), "built on the restore");
    assert_eq!(p.write_rule("note"), Role::Viewer);
}
