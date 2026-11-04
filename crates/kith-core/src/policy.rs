//! Write permissions: the policy object (phase 6, REQ-PERM-001/002/004, ADR 0006).
//!
//! Every org has one policy object (type [`POLICY_TYPE`], ID [`policy_object_id`]).
//! Each of its changes carries one [`PolicyOp`]. [`Policy::fold`] turns the
//! object's changes into the current [`Policy`] deterministically: changes are
//! applied in causal order, concurrent ones by seniority (the org creator first,
//! then admins in the order they became admins) and then change ID, and an op only
//! counts if its author is an admin at that point. So every device that has the
//! same policy changes reaches the same policy, whatever the arrival order.
//!
//! Roles are fixed: [`Role::Viewer`] < [`Role::Editor`] < [`Role::Admin`]. Each
//! object type has a minimum write role (default [`Role::Editor`]). Members not
//! named in the policy are editors. Restricting a device (revoke or demote) keeps
//! exactly the changes the admin had seen from it (the keep list); every other
//! change by that device is judged by its new role ("revocation wins").

use std::collections::{BTreeMap, BTreeSet, HashSet};

use sha2::{Digest, Sha256};

use crate::membership::MembershipCert;
use crate::{Change, ChangeId, DeviceId, ObjectId};

/// Object type of the policy object.
pub const POLICY_TYPE: &str = "kith.policy";

/// The policy object's ID for an org (derived, so every device finds it).
pub fn policy_object_id(org: &DeviceId) -> ObjectId {
    let h = Sha256::new()
        .chain_update(b"kith/policy/v1\0")
        .chain_update(org.0)
        .finalize();
    ObjectId(h[..16].try_into().expect("16 bytes"))
}

/// A member's role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// May read; may write only types whose rule is `Viewer`.
    Viewer,
    /// May write ordinary objects (the default for members).
    Editor,
    /// May change the policy and admit devices.
    Admin,
}

impl Role {
    fn code(self) -> u8 {
        match self {
            Role::Viewer => 0,
            Role::Editor => 1,
            Role::Admin => 2,
        }
    }
    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Role::Viewer,
            1 => Role::Editor,
            2 => Role::Admin,
            _ => return None,
        })
    }
    /// Lower-case name (`viewer`, `editor`, `admin`).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
        }
    }
    /// Parse [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "viewer" => Role::Viewer,
            "editor" => Role::Editor,
            "admin" => Role::Admin,
            _ => return None,
        })
    }
}

/// One change of the policy object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyOp {
    /// The first op: the org creator's root-signed admin certificate.
    Genesis {
        /// Root → creator admin certificate; its device must be the change's author.
        admin: MembershipCert,
    },
    /// Give `device` a role. Making an admin needs the root-signed admin
    /// certificate for that device (only the root makes admins, ADR 0005).
    SetRole {
        /// The device.
        device: DeviceId,
        /// Its new role.
        role: Role,
        /// Required for `Role::Admin`.
        cert: Option<MembershipCert>,
    },
    /// The minimum role that may write objects of `object_type`.
    SetRule {
        /// The object type.
        object_type: String,
        /// Minimum write role.
        write: Role,
    },
    /// Revoke (`role: None`) or demote `device`. Its changes in `keep` (the ones the
    /// admin had seen) stay valid; all others are judged by the new role.
    Restrict {
        /// The device.
        device: DeviceId,
        /// New role, or `None` for no access at all.
        role: Option<Role>,
        /// Change IDs by `device` that remain valid.
        keep: Vec<ChangeId>,
    },
}

/// Malformed policy payload.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed policy op: {0}")]
pub struct PolicyError(&'static str);

const VERSION: u8 = 1;

impl PolicyOp {
    /// Payload bytes for a policy change.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = vec![VERSION];
        let cert = |w: &mut Vec<u8>, c: &MembershipCert| {
            w.extend_from_slice(
                &crate::membership::CertChain(vec![c.clone()])
                    .to_hex()
                    .into_bytes(),
            )
        };
        match self {
            PolicyOp::Genesis { admin } => {
                w.push(0);
                cert(&mut w, admin);
            }
            PolicyOp::SetRole {
                device,
                role,
                cert: c,
            } => {
                w.push(1);
                w.extend_from_slice(&device.0);
                w.push(role.code());
                if let Some(c) = c {
                    cert(&mut w, c);
                }
            }
            PolicyOp::SetRule { object_type, write } => {
                w.push(2);
                w.push(write.code());
                w.extend_from_slice(object_type.as_bytes());
            }
            PolicyOp::Restrict { device, role, keep } => {
                w.push(3);
                w.extend_from_slice(&device.0);
                w.push(role.map_or(0xff, Role::code));
                for id in keep {
                    w.extend_from_slice(&id.0);
                }
            }
        }
        w
    }

    /// Parse [`Self::encode`].
    pub fn decode(b: &[u8]) -> Result<Self, PolicyError> {
        let (&v, rest) = b.split_first().ok_or(PolicyError("empty"))?;
        if v != VERSION {
            return Err(PolicyError("unknown version"));
        }
        let (&kind, rest) = rest.split_first().ok_or(PolicyError("no kind"))?;
        let cert = |b: &[u8]| -> Result<MembershipCert, PolicyError> {
            let s = std::str::from_utf8(b).map_err(|_| PolicyError("certificate"))?;
            let mut chain = crate::membership::CertChain::from_hex(s)
                .map_err(|_| PolicyError("certificate"))?;
            if chain.0.len() != 1 {
                return Err(PolicyError("certificate"));
            }
            Ok(chain.0.remove(0))
        };
        let device = |b: &[u8]| -> Result<DeviceId, PolicyError> {
            Ok(DeviceId(
                b.get(..32)
                    .ok_or(PolicyError("device"))?
                    .try_into()
                    .expect("32"),
            ))
        };
        Ok(match kind {
            0 => PolicyOp::Genesis { admin: cert(rest)? },
            1 => {
                let d = device(rest)?;
                let role = Role::from_code(*rest.get(32).ok_or(PolicyError("role"))?)
                    .ok_or(PolicyError("role"))?;
                let tail = &rest[33..];
                PolicyOp::SetRole {
                    device: d,
                    role,
                    cert: if tail.is_empty() {
                        None
                    } else {
                        Some(cert(tail)?)
                    },
                }
            }
            2 => {
                let write = Role::from_code(*rest.first().ok_or(PolicyError("role"))?)
                    .ok_or(PolicyError("role"))?;
                let object_type = std::str::from_utf8(&rest[1..])
                    .map_err(|_| PolicyError("object type"))?
                    .to_string();
                if object_type.is_empty() || object_type == POLICY_TYPE {
                    return Err(PolicyError("object type"));
                }
                PolicyOp::SetRule { object_type, write }
            }
            3 => {
                let d = device(rest)?;
                let role = match *rest.get(32).ok_or(PolicyError("role"))? {
                    0xff => None,
                    c => Some(Role::from_code(c).ok_or(PolicyError("role"))?),
                };
                let ids = &rest[33..];
                if ids.len() % 32 != 0 {
                    return Err(PolicyError("keep list"));
                }
                PolicyOp::Restrict {
                    device: d,
                    role,
                    keep: ids
                        .chunks(32)
                        .map(|c| ChangeId(c.try_into().expect("32")))
                        .collect(),
                }
            }
            _ => return Err(PolicyError("unknown kind")),
        })
    }
}

/// The current permissions of an org.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The org creator (author of the accepted genesis), if known.
    pub creator: Option<DeviceId>,
    /// Explicit roles; members not listed are editors.
    pub roles: BTreeMap<DeviceId, Role>,
    /// Revoked devices (no access).
    pub revoked: BTreeSet<DeviceId>,
    /// Minimum write role per object type (default editor).
    pub rules: BTreeMap<String, Role>,
    /// Changes kept valid by restrictions, per restricted device.
    pub kept: BTreeMap<DeviceId, HashSet<ChangeId>>,
    /// Admins in the order they became admins (seniority; creator first).
    pub admin_order: Vec<DeviceId>,
    /// The policy changes that counted.
    pub accepted: BTreeSet<ChangeId>,
}

impl Policy {
    /// A device's current role; `None` if revoked.
    pub fn role_of(&self, device: &DeviceId) -> Option<Role> {
        if self.revoked.contains(device) {
            return None;
        }
        Some(self.roles.get(device).copied().unwrap_or(Role::Editor))
    }

    /// Minimum role to write objects of `object_type`.
    pub fn write_rule(&self, object_type: &str) -> Role {
        if object_type == POLICY_TYPE {
            return Role::Admin;
        }
        self.rules.get(object_type).copied().unwrap_or(Role::Editor)
    }

    /// May `change`'s author have made it, under this policy? (Policy changes
    /// themselves are judged by [`Self::fold`], see [`Self::accepted`].)
    pub fn allows(&self, change: &Change) -> bool {
        let author = &change.author;
        if self
            .kept
            .get(author)
            .is_some_and(|k| k.contains(&change.change_id))
        {
            return true;
        }
        self.role_of(author)
            .is_some_and(|r| r >= self.write_rule(change.body.object_type.as_str()))
    }

    fn seniority(&self, device: &DeviceId) -> usize {
        self.admin_order
            .iter()
            .position(|d| d == device)
            .unwrap_or(usize::MAX)
    }

    fn is_admin(&self, device: &DeviceId) -> bool {
        self.role_of(device) == Some(Role::Admin)
    }

    /// Compute the policy of `org` from its policy object's changes (any order).
    /// Changes that are not valid policy changes are ignored.
    pub fn fold(org: &DeviceId, changes: &[Change]) -> Policy {
        let mut p = Policy::default();
        let ids: HashSet<ChangeId> = changes.iter().map(|c| c.change_id).collect();
        // Kahn's algorithm over the parent links inside the policy object.
        let mut pending: Vec<&Change> = changes.iter().collect();
        let mut done: HashSet<ChangeId> = HashSet::new();
        while !pending.is_empty() {
            let ready: Vec<usize> = (0..pending.len())
                .filter(|&i| {
                    pending[i]
                        .body
                        .parents
                        .iter()
                        .all(|par| done.contains(par) || !ids.contains(par))
                })
                .collect();
            if ready.is_empty() {
                break; // a cycle cannot happen with hashes; stop defensively
            }
            // Concurrent ops: senior authors first, then lowest change ID.
            let pick = *ready
                .iter()
                .min_by_key(|&&i| (p.seniority(&pending[i].author), pending[i].change_id))
                .expect("non-empty");
            let c = pending.swap_remove(pick);
            done.insert(c.change_id);
            if p.apply(org, c) {
                p.accepted.insert(c.change_id);
            }
        }
        p
    }

    /// Apply one policy change if it is valid at this point; returns whether it counted.
    fn apply(&mut self, org: &DeviceId, c: &Change) -> bool {
        if c.body.object_type.as_str() != POLICY_TYPE
            || c.body.object_id != policy_object_id(org)
            || c.body.scope != crate::Scope::org(org)
        {
            return false;
        }
        let Ok(op) = PolicyOp::decode(&c.body.payload) else {
            return false;
        };
        let author = c.author;
        let root_admin = |cert: &MembershipCert, device: &DeviceId| {
            cert.org == *org
                && cert.issuer == *org
                && cert.admin
                && cert.device == *device
                && crate::membership::CertChain(vec![cert.clone()])
                    .verify(org, device)
                    .is_ok()
        };
        match op {
            PolicyOp::Genesis { admin } => {
                if self.creator.is_some() || !root_admin(&admin, &author) {
                    return false;
                }
                self.creator = Some(author);
                self.roles.insert(author, Role::Admin);
                self.admin_order.push(author);
                true
            }
            _ if self.creator.is_none() || !self.is_admin(&author) => false,
            PolicyOp::SetRole { device, role, cert } => {
                if role == Role::Admin && !cert.is_some_and(|c| root_admin(&c, &device)) {
                    return false;
                }
                // Taking rights away goes through Restrict (it needs a keep list).
                if self.role_of(&device).is_some_and(|old| role < old) {
                    return false;
                }
                if self.creator == Some(device) {
                    return false;
                }
                self.revoked.remove(&device);
                self.roles.insert(device, role);
                if role == Role::Admin && !self.admin_order.contains(&device) {
                    self.admin_order.push(device);
                }
                true
            }
            PolicyOp::SetRule { object_type, write } => {
                self.rules.insert(object_type, write);
                true
            }
            PolicyOp::Restrict { device, role, keep } => {
                // The creator can't be restricted, and an admin can't restrict a
                // more senior admin ("the root always wins, seniority wins").
                if self.creator == Some(device)
                    || (self.is_admin(&device) && self.seniority(&device) < self.seniority(&author))
                {
                    return false;
                }
                match role {
                    None => {
                        self.revoked.insert(device);
                    }
                    Some(r) => {
                        self.revoked.remove(&device);
                        self.roles.insert(device, r);
                    }
                }
                if role != Some(Role::Admin) {
                    self.admin_order.retain(|d| *d != device);
                }
                self.kept.entry(device).or_default().extend(keep);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
            &creator,
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
        let demote = org.op(
            &creator,
            vec![rule.change_id],
            PolicyOp::Restrict {
                device: viewer.device_id(),
                role: Some(Role::Viewer),
                keep: vec![],
            },
        );
        let p = Policy::fold(&org.id, &[demote.clone(), g.clone(), rule.clone()]);
        assert_eq!(p.accepted.len(), 3);
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
            &[g.clone(), rule.clone(), demote.clone(), sneaky.clone()],
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
    }

    /// req: REQ-PERM-004
    #[test]
    fn revocation_keeps_only_what_the_admin_had_seen() {
        let org = Org::new();
        let (creator, bob) = (key(), key());
        let seen = data(&bob, "note");
        let offline = data(&bob, "note");
        let g = org.op(
            &creator,
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
            &creator,
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

    #[test]
    fn policy_ids_differ_per_org() {
        assert_ne!(
            policy_object_id(&Org::new().id),
            policy_object_id(&Org::new().id)
        );
    }
}
