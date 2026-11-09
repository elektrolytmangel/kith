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
    let mut id = [0u8; 16];
    id.copy_from_slice(&h[..16]);
    ObjectId(id)
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
    /// How much history objects of `object_type` keep (REQ-DATA-005, ADR 0026). Admins
    /// create snapshots of what the rule lets go; the default keeps everything.
    SetRetention {
        /// The object type.
        object_type: String,
        /// The rule.
        retention: Retention,
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

/// How much of an object's history is kept (REQ-DATA-005, ADR 0026).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Retention {
    /// Keep every change (the default).
    #[default]
    KeepAll,
    /// Keep the newest `n` changes of each object; fold the rest into snapshots.
    /// `0` folds everything (documents), or keeps only the heads (raw objects).
    KeepLast(u32),
    /// Keep changes from the last `n` days.
    KeepDays(u32),
}

impl Retention {
    fn code(self) -> (u8, u32) {
        match self {
            Retention::KeepAll => (0, 0),
            Retention::KeepLast(n) => (1, n),
            Retention::KeepDays(n) => (2, n),
        }
    }

    fn from_code(kind: u8, n: u32) -> Option<Self> {
        Some(match kind {
            0 if n == 0 => Retention::KeepAll,
            1 => Retention::KeepLast(n),
            2 => Retention::KeepDays(n),
            _ => return None,
        })
    }

    /// Parse `"all"`, `"last:500"` or `"days:90"`.
    pub fn parse(s: &str) -> Option<Self> {
        if s == "all" {
            return Some(Retention::KeepAll);
        }
        let (kind, n) = s.split_once(':')?;
        let n: u32 = n.parse().ok()?;
        match kind {
            "last" => Some(Retention::KeepLast(n)),
            "days" => Some(Retention::KeepDays(n)),
            _ => None,
        }
    }
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
            PolicyOp::SetRetention {
                object_type,
                retention,
            } => {
                w.push(6);
                let (kind, n) = retention.code();
                w.push(kind);
                w.extend_from_slice(&n.to_be_bytes());
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
            crate::array_at(b, 0)
                .map(DeviceId)
                .ok_or(PolicyError("device"))
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
            6 => {
                let kind = *rest.first().ok_or(PolicyError("retention"))?;
                let n =
                    u32::from_be_bytes(crate::array_at(rest, 1).ok_or(PolicyError("retention"))?);
                let retention = Retention::from_code(kind, n).ok_or(PolicyError("retention"))?;
                let object_type = std::str::from_utf8(&rest[5..])
                    .map_err(|_| PolicyError("object type"))?
                    .to_string();
                if object_type.is_empty() || object_type == POLICY_TYPE {
                    return Err(PolicyError("object type"));
                }
                PolicyOp::SetRetention {
                    object_type,
                    retention,
                }
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
                        .as_chunks::<32>()
                        .0
                        .iter()
                        .map(|c| ChangeId(*c))
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
                let count =
                    u32::from_be_bytes(crate::array_at(rest, 0).ok_or(PolicyError("members"))?)
                        as usize;
                let rest = &rest[4..];
                if rest.len() < count * 32 || !(rest.len() - count * 32).is_multiple_of(32) {
                    return Err(PolicyError("members"));
                }
                let (m, k) = rest.split_at(count * 32);
                PolicyOp::SetSubgroup {
                    name,
                    members: m.as_chunks::<32>().0.iter().map(|c| DeviceId(*c)).collect(),
                    keep: k.as_chunks::<32>().0.iter().map(|c| ChangeId(*c)).collect(),
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
    /// History retention per object type (default: keep everything).
    pub retention: BTreeMap<String, Retention>,
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

    /// How much history objects of `object_type` keep.
    pub fn retention_for(&self, object_type: &str) -> Retention {
        self.retention.get(object_type).copied().unwrap_or_default()
    }

    /// Is `device` an admin under this policy?
    pub fn is_admin_device(&self, device: &DeviceId) -> bool {
        self.is_admin(device)
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
            let Some(&pick) = ready
                .iter()
                .min_by_key(|&&i| (p.seniority(&pending[i].author), pending[i].change_id))
            else {
                break;
            };
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
            PolicyOp::SetRetention {
                object_type,
                retention,
            } => {
                self.retention.insert(object_type, retention);
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
mod tests;
