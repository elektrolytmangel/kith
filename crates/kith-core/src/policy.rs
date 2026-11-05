//! Write permissions: the policy object (phase 6, REQ-PERM-001/002/004, ADR 0006).
//!
//! Every org has one policy object (type [`POLICY_TYPE`], ID [`policy_object_id`]).
//! Each of its changes carries one [`PolicyOp`]. [`Policy::fold`] turns the
//! object's changes into the current [`Policy`] deterministically. The
//! [`PolicyOp::Genesis`] signed by the org root key names the creator. The other
//! changes are applied in causal order, concurrent ones by seniority (the creator
//! first, then admins in the order they became admins) and then change ID, and an
//! op only counts if its author is an admin at that point. So every device that
//! has the same policy changes reaches the same policy, whatever the arrival order.
//!
//! Roles are fixed: [`Role::Viewer`] < [`Role::Editor`] < [`Role::Admin`]. Each
//! object type has a minimum write role (default [`Role::Editor`]). Only devices
//! the policy names (or links) have a role: admins name each device they admit.
//! Restricting a device (revoke or demote) keeps exactly the changes the admin had
//! seen from it (the keep list); every other change by that device is judged by its
//! new role, and its policy changes the admin had not seen don't count ("revocation
//! wins"). Only an admin at least as senior as the one who restricted a device may
//! raise its role again.

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
    /// The first op: the org creator's root-signed admin certificate. The change
    /// itself must be signed by the org root key (its author is the org ID), so no
    /// other admin can write one. Without it no policy change counts.
    Genesis {
        /// Root → creator admin certificate; its device is the creator.
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
    /// Create subgroup `name` (scope `<org>/<name>`, read-restricted, REQ-PERM-003)
    /// or replace its member list. The author of the first `SetSubgroup` for a
    /// name is the subgroup's owner: the device that adds and removes members in
    /// its MLS group. Changes in the subgroup by removed members stay valid only if
    /// listed in `keep`.
    SetSubgroup {
        /// Subgroup name (`a-z 0-9 - _ .`, 1-64).
        name: String,
        /// The devices that may read and write it.
        members: Vec<DeviceId>,
        /// Changes in the subgroup by removed members that stay valid.
        keep: Vec<ChangeId>,
    },
    /// The author links `device` as another device of the same user (ADR 0011,
    /// REQ-ID-002). Any member may do it for its own device; the device then has
    /// the author's role, at most editor, and is revoked or demoted with it.
    LinkDevice {
        /// The new device.
        device: DeviceId,
    },
    /// Revoke (`role: None`) or demote `device` (`role` below its current one). Its
    /// changes in `keep` (the ones the admin had seen) stay valid; all others are
    /// judged by the new role.
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
            PolicyOp::SetSubgroup {
                name,
                members,
                keep,
            } => {
                w.push(4);
                w.push(name.len() as u8);
                w.extend_from_slice(name.as_bytes());
                w.extend_from_slice(&(members.len() as u32).to_be_bytes());
                for m in members {
                    w.extend_from_slice(&m.0);
                }
                for id in keep {
                    w.extend_from_slice(&id.0);
                }
            }
            PolicyOp::LinkDevice { device } => {
                w.push(5);
                w.extend_from_slice(&device.0);
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
            4 => {
                let (&n, rest) = rest.split_first().ok_or(PolicyError("name"))?;
                let n = n as usize;
                let name = std::str::from_utf8(rest.get(..n).ok_or(PolicyError("name"))?)
                    .map_err(|_| PolicyError("name"))?
                    .to_string();
                let valid = !name.is_empty()
                    && name.len() <= 64
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b)
                    });
                if !valid {
                    return Err(PolicyError("name"));
                }
                let rest = &rest[n..];
                let count = u32::from_be_bytes(
                    rest.get(..4)
                        .ok_or(PolicyError("members"))?
                        .try_into()
                        .expect("4"),
                ) as usize;
                let rest = &rest[4..];
                if rest.len() < count * 32 || !(rest.len() - count * 32).is_multiple_of(32) {
                    return Err(PolicyError("members"));
                }
                let (m, k) = rest.split_at(count * 32);
                PolicyOp::SetSubgroup {
                    name,
                    members: m
                        .chunks(32)
                        .map(|c| DeviceId(c.try_into().expect("32")))
                        .collect(),
                    keep: k
                        .chunks(32)
                        .map(|c| ChangeId(c.try_into().expect("32")))
                        .collect(),
                }
            }
            5 => {
                if rest.len() != 32 {
                    return Err(PolicyError("device"));
                }
                PolicyOp::LinkDevice {
                    device: device(rest)?,
                }
            }
            _ => return Err(PolicyError("unknown kind")),
        })
    }
}

/// Is `cert` the root-signed admin certificate of `device` in `org`?
fn root_admin(org: &DeviceId, cert: &MembershipCert, device: &DeviceId) -> bool {
    cert.org == *org
        && cert.issuer == *org
        && cert.admin
        && cert.device == *device
        && crate::membership::CertChain(vec![cert.clone()])
            .verify(org, device)
            .is_ok()
}

/// The current permissions of an org.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    /// The org creator (author of the accepted genesis), if known.
    pub creator: Option<DeviceId>,
    /// Explicit roles. Devices neither listed nor linked have no role.
    pub roles: BTreeMap<DeviceId, Role>,
    /// Linked devices: device → the member device it was linked to (its user).
    pub links: BTreeMap<DeviceId, DeviceId>,
    /// Revoked devices (no access).
    pub revoked: BTreeSet<DeviceId>,
    /// Minimum write role per object type (default editor).
    pub rules: BTreeMap<String, Role>,
    /// Changes kept valid by restrictions, per restricted device.
    pub kept: BTreeMap<DeviceId, HashSet<ChangeId>>,
    /// Restricted devices → the admin who last restricted them. Only an admin at
    /// least as senior may raise the device's role again.
    pub restricted_by: BTreeMap<DeviceId, DeviceId>,
    /// Admins in the order they became admins (seniority; creator first).
    pub admin_order: Vec<DeviceId>,
    /// Subgroups: name → members.
    pub subgroups: BTreeMap<String, BTreeSet<DeviceId>>,
    /// Subgroup owners (author of the first `SetSubgroup` for the name).
    pub subgroup_owners: BTreeMap<String, DeviceId>,
    /// Changes in subgroups kept valid after their authors were removed.
    pub subgroup_kept: HashSet<ChangeId>,
    /// The policy changes that counted.
    pub accepted: BTreeSet<ChangeId>,
}

impl Policy {
    /// A device's current role; `None` if revoked.
    pub fn role_of(&self, device: &DeviceId) -> Option<Role> {
        if self.revoked.contains(device) {
            return None;
        }
        if let Some(r) = self.roles.get(device) {
            return Some(*r);
        }
        // A linked device has its user's role, but is never made admin by the link.
        self.links
            .get(device)
            .and_then(|primary| self.role_of(primary))
            .map(|r| r.min(Role::Editor))
    }

    /// The devices linked to `device` (its user's other devices).
    pub fn linked_to(&self, device: &DeviceId) -> Vec<DeviceId> {
        self.links
            .iter()
            .filter(|(_, p)| *p == device)
            .map(|(d, _)| *d)
            .collect()
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
        // A subgroup's data: only its members (or kept changes of former members).
        if let Some(name) = change.body.scope.subgroup_name() {
            let member = self.subgroups.get(name).is_some_and(|m| m.contains(author));
            if !member {
                return self.subgroup_kept.contains(&change.change_id);
            }
        }
        self.role_of(author)
            .is_some_and(|r| r >= self.write_rule(change.body.object_type.as_str()))
    }

    /// The members of subgroup `name`, if it exists.
    pub fn subgroup(&self, name: &str) -> Option<&BTreeSet<DeviceId>> {
        self.subgroups.get(name)
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

    /// May `author` raise the role of a device that `by` restricted?
    fn may_override(&self, author: &DeviceId, by: &DeviceId) -> bool {
        self.creator == Some(*author) || self.seniority(author) <= self.seniority(by)
    }

    /// Compute the policy of `org` from its policy object's changes (any order).
    /// Changes that are not valid policy changes are ignored.
    pub fn fold(org: &DeviceId, changes: &[Change]) -> Policy {
        // "Revocation wins": a restricted admin's policy changes that the
        // restricting admin had not seen (concurrent ones, or ones built on old
        // parents) don't count, even if the causal order applied them first. Fold
        // again without them until nothing changes (the excluded set only grows).
        let mut excluded = HashSet::new();
        loop {
            let p = Self::fold_excluding(org, changes, &excluded);
            let late = p.unseen_ops_of_restricted(changes);
            if late.is_empty() {
                return p;
            }
            excluded.extend(late);
        }
    }

    /// The creator named by `c`, if `c` is a genesis signed by the org root key.
    fn root_genesis(org: &DeviceId, c: &Change) -> Option<DeviceId> {
        if c.author != *org || !Self::in_policy_object(org, c) {
            return None;
        }
        match PolicyOp::decode(&c.body.payload) {
            Ok(PolicyOp::Genesis { admin }) if root_admin(org, &admin, &admin.device) => {
                Some(admin.device)
            }
            _ => None,
        }
    }

    fn in_policy_object(org: &DeviceId, c: &Change) -> bool {
        c.body.object_type.as_str() == POLICY_TYPE
            && c.body.object_id == policy_object_id(org)
            && c.body.scope == crate::Scope::org(org)
    }

    fn fold_excluding(org: &DeviceId, changes: &[Change], excluded: &HashSet<ChangeId>) -> Policy {
        let mut p = Policy::default();
        // The genesis is pinned: the root-signed one (lowest change ID if the root
        // signed several). Every other genesis is ignored.
        if let Some((g, creator)) = changes
            .iter()
            .filter_map(|c| Self::root_genesis(org, c).map(|d| (c.change_id, d)))
            .min()
        {
            p.creator = Some(creator);
            p.roles.insert(creator, Role::Admin);
            p.admin_order.push(creator);
            p.accepted.insert(g);
        }
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
            if !excluded.contains(&c.change_id) && p.apply(org, c) {
                p.accepted.insert(c.change_id);
            }
        }
        p
    }

    /// Accepted policy changes by a device that an accepted `Restrict` took admin
    /// rights from, which are neither ancestors nor descendants of that `Restrict`.
    fn unseen_ops_of_restricted(&self, changes: &[Change]) -> HashSet<ChangeId> {
        let parents: std::collections::HashMap<ChangeId, &[ChangeId]> = changes
            .iter()
            .map(|c| (c.change_id, c.body.parents.as_slice()))
            .collect();
        let ancestors = |start: ChangeId| {
            let mut seen = HashSet::new();
            let mut stack = vec![start];
            while let Some(id) = stack.pop() {
                for par in parents.get(&id).copied().unwrap_or_default() {
                    if seen.insert(*par) {
                        stack.push(*par);
                    }
                }
            }
            seen
        };
        let mut late = HashSet::new();
        for r in changes
            .iter()
            .filter(|c| self.accepted.contains(&c.change_id))
        {
            let Ok(PolicyOp::Restrict { device, role, .. }) = PolicyOp::decode(&r.body.payload)
            else {
                continue;
            };
            if role == Some(Role::Admin) {
                continue;
            }
            let seen = ancestors(r.change_id);
            for o in changes {
                if o.author == device
                    && self.accepted.contains(&o.change_id)
                    && !seen.contains(&o.change_id)
                    && !ancestors(o.change_id).contains(&r.change_id)
                {
                    late.insert(o.change_id);
                }
            }
        }
        late
    }

    /// Apply one policy change if it is valid at this point; returns whether it counted.
    fn apply(&mut self, org: &DeviceId, c: &Change) -> bool {
        if !Self::in_policy_object(org, c) {
            return false;
        }
        let Ok(op) = PolicyOp::decode(&c.body.payload) else {
            return false;
        };
        let author = c.author;
        match op {
            // The pinned genesis is applied before everything else (see `fold`).
            PolicyOp::Genesis { .. } => false,
            _ if self.creator.is_none() => false,
            PolicyOp::LinkDevice { device } => {
                // Any current member may link a device of its own. Not a device that
                // already has a role or link, and links do not chain.
                if self.role_of(&author).is_none()
                    || self.links.contains_key(&author)
                    || device == author
                    || self.links.contains_key(&device)
                    || self.roles.contains_key(&device)
                    || self.revoked.contains(&device)
                    || self.creator == Some(device)
                    || self.links.values().any(|p| *p == device)
                {
                    return false;
                }
                self.links.insert(device, author);
                true
            }
            _ if !self.is_admin(&author) => false,
            PolicyOp::SetRole { device, role, cert } => {
                if role == Role::Admin && !cert.is_some_and(|c| root_admin(org, &c, &device)) {
                    return false;
                }
                // Taking rights away goes through Restrict (it needs a keep list).
                if self.role_of(&device).is_some_and(|old| role < old) {
                    return false;
                }
                if self.creator == Some(device) {
                    return false;
                }
                // Undoing a restriction: seniority wins, as for Restrict itself.
                if self
                    .restricted_by
                    .get(&device)
                    .is_some_and(|by| !self.may_override(&author, by))
                {
                    return false;
                }
                self.restricted_by.remove(&device);
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
            PolicyOp::SetSubgroup {
                name,
                members,
                keep,
            } => {
                self.subgroup_owners.entry(name.clone()).or_insert(author);
                self.subgroups.insert(name, members.into_iter().collect());
                self.subgroup_kept.extend(keep);
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
                // Restrict only lowers a role; raising one goes through SetRole.
                if let Some(r) = role
                    && self.role_of(&device).is_none_or(|old| r >= old)
                {
                    return false;
                }
                match role {
                    None => {
                        self.revoked.insert(device);
                    }
                    Some(r) => {
                        self.roles.insert(device, r);
                    }
                }
                self.restricted_by.insert(device, author);
                if role != Some(Role::Admin) {
                    self.admin_order.retain(|d| *d != device);
                }
                for linked in self.linked_to(&device) {
                    self.kept
                        .entry(linked)
                        .or_default()
                        .extend(keep.iter().copied());
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
}
