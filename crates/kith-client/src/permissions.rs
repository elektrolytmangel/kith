//! Roles, write rules, revocation and subgroups (phase 6, ADR 0006).

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    // ---- permissions (phase 6, ADR 0006) ----

    /// The current policy of `org`, if this device has it.
    pub fn policy(&self, org: &str) -> Option<&Policy> {
        self.policies.get(org)
    }

    /// A device's role in `org` (`None`: revoked or not a member). Devices the
    /// policy does not name have no role; without a policy everyone is an editor.
    pub fn role_of(&self, org: &str, device: &str) -> Result<Option<Role>, ClientError> {
        let d = DeviceId::from_hex(device)?;
        Ok(self
            .policies
            .get(org)
            .map_or(Some(Role::Editor), |p| p.role_of(&d)))
    }

    /// Set a member's role. Raising to admin needs the org root key (only the
    /// creator can); lowering keeps the member's changes this device has seen.
    /// Broadcast the returned change like any other.
    pub fn set_role(&mut self, org: &str, device: &str, role: Role) -> Result<Change, ClientError> {
        let d = DeviceId::from_hex(device)?;
        let current = self.role_of(org, device)?;
        let op = if current.is_some_and(|c| role < c) {
            PolicyOp::Restrict {
                device: d,
                role: Some(role),
                keep: self.changes_by_user(org, &d)?,
            }
        } else {
            let cert = if role == Role::Admin {
                Some(self.root_admin_cert(org, d)?)
            } else {
                None
            };
            PolicyOp::SetRole {
                device: d,
                role,
                cert,
            }
        };
        self.policy_commit(org, op)
    }

    /// Set the minimum role that may write objects of `object_type` in `org`.
    /// Broadcast the returned change.
    pub fn set_write_rule(
        &mut self,
        org: &str,
        object_type: &str,
        write: Role,
    ) -> Result<Change, ClientError> {
        self.policy_commit(
            org,
            PolicyOp::SetRule {
                object_type: object_type.into(),
                write,
            },
        )
    }

    /// Revoke a device's write access in `org` (REQ-INV-004). Changes of it that
    /// this device has already seen stay valid; all others are rejected everywhere.
    /// Usually via [`Self::remove_member`], which also removes it from the group.
    pub fn revoke(&mut self, org: &str, device: &str) -> Result<Change, ClientError> {
        let d = DeviceId::from_hex(device)?;
        let keep = self.changes_by_user(org, &d)?;
        self.policy_commit(
            org,
            PolicyOp::Restrict {
                device: d,
                role: None,
                keep,
            },
        )
    }

    /// Create read-restricted subgroup `name` of `org` with `members` (hex; this
    /// device is always included) (REQ-PERM-003). Admins only. This device becomes
    /// the subgroup's owner: it runs its MLS group and must be online for members to
    /// be added (they send it their KeyPackage once they see the policy). Data in
    /// scope `org/name` ([`Scope::subgroup`]) only reaches members. Send the frames.
    pub fn create_subgroup(
        &mut self,
        org: &str,
        name: &str,
        members: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        Scope::subgroup(&org_id, name).map_err(|e| ClientError::Forbidden(e.to_string()))?;
        if self
            .policies
            .get(org)
            .is_some_and(|p| p.subgroup(name).is_some())
        {
            return Err(ClientError::Forbidden(format!("subgroup {name} exists")));
        }
        self.set_subgroup_members(org, name, members)
    }

    /// Replace the members of subgroup `name` (hex IDs; admins only). Removed
    /// members keep the subgroup changes this device has seen; the owner removes them
    /// from the MLS group, so they cannot read anything new. Send the frames.
    pub fn set_subgroup_members(
        &mut self,
        org: &str,
        name: &str,
        members: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        let scope =
            Scope::subgroup(&org_id, name).map_err(|e| ClientError::Forbidden(e.to_string()))?;
        let mut list: Vec<DeviceId> = members
            .iter()
            .map(|m| DeviceId::from_hex(m))
            .collect::<Result<_, _>>()?;
        let me = self.device_id();
        let owner = self
            .policies
            .get(org)
            .and_then(|p| p.subgroup_owners.get(name).copied())
            .unwrap_or(me);
        for d in [me, owner] {
            if !list.contains(&d) {
                list.push(d);
            }
        }
        list.sort();
        list.dedup();
        // Changes by members being removed that we have seen stay valid.
        let mut keep = vec![];
        for id in self.store.scope_ids(&scope)? {
            if !self.invalid.contains(&id)
                && let Some(c) = self.store.get(&id)?
                && !list.contains(&c.author)
            {
                keep.push(id);
            }
        }
        let change = self.policy_commit(
            org,
            PolicyOp::SetSubgroup {
                name: name.into(),
                members: list,
                keep,
            },
        )?;
        let mut frames = vec![self.broadcast_frame(org, &change)?];
        frames.extend(self.subgroup_tasks()?);
        Ok(frames)
    }

    /// Members (hex) of subgroup `name` of `org` per the policy, if it exists.
    pub fn subgroup_members(&self, org: &str, name: &str) -> Option<Vec<String>> {
        self.policies
            .get(org)?
            .subgroup(name)
            .map(|m| m.iter().map(DeviceId::to_hex).collect())
    }

    /// Subgroups of `org` this device can read (it is in their MLS group).
    pub fn my_subgroups(&self, org: &str) -> Vec<String> {
        self.groups
            .orgs()
            .into_iter()
            .filter_map(|g| {
                let name = g.strip_prefix(org)?.strip_prefix('/')?.to_string();
                self.groups.is_member(&g).then_some(name)
            })
            .collect()
    }

    /// Changes by `device` and by the devices linked to it (one user, ADR 0011).
    pub(crate) fn changes_by_user(
        &self,
        org: &str,
        device: &DeviceId,
    ) -> Result<Vec<ChangeId>, ClientError> {
        let mut out = self.changes_by(device)?;
        for linked in self
            .policies
            .get(org)
            .map_or(vec![], |p| p.linked_to(device))
        {
            out.extend(self.changes_by(&linked)?);
        }
        out.sort();
        Ok(out)
    }

    pub(crate) fn changes_by(&self, device: &DeviceId) -> Result<Vec<ChangeId>, ClientError> {
        let mut out = Vec::new();
        for id in self.store.all_ids()? {
            if !self.invalid.contains(&id)
                && let Some(c) = self.store.get(&id)?
                && c.author == *device
            {
                out.push(id);
            }
        }
        out.sort();
        Ok(out)
    }

    pub(crate) fn root_admin_cert(
        &self,
        org: &str,
        device: DeviceId,
    ) -> Result<MembershipCert, ClientError> {
        let root = self
            .orgs
            .0
            .get(org)
            .and_then(|s| s.root)
            .ok_or_else(|| ClientError::NotAdmin(org.into()))?;
        let root = DeviceKey::from_secret_bytes(&root);
        Ok(MembershipCert::issue(
            &root,
            root.device_id(),
            device,
            true,
            now_ms(),
        ))
    }

    /// Append `op` to `org`'s policy object. Fails unless the op counts (we are an
    /// admin and it is valid), so a refused op never leaves the device.
    pub(crate) fn policy_commit(&mut self, org: &str, op: PolicyOp) -> Result<Change, ClientError> {
        self.policy_commit_by(org, op, None)
    }

    /// [`Self::policy_commit`], signed by the org root key `root` if given (the
    /// genesis), else by this device.
    pub(crate) fn policy_commit_by(
        &mut self,
        org: &str,
        op: PolicyOp,
        root: Option<&DeviceKey>,
    ) -> Result<Change, ClientError> {
        let signer: &dyn Signer = match root {
            Some(r) => r,
            None => &self.key,
        };
        let org_id = DeviceId::from_hex(org)?;
        let pid = policy_object_id(&org_id);
        let parents = self.store.heads(&pid)?;
        let change = Change::sign(
            UnsignedChange {
                scope: Scope::org(&org_id),
                object_id: pid,
                object_type: ObjectType::new(POLICY_TYPE),
                parents,
                timestamp_ms: now_ms(),
                payload: op.encode(),
            },
            signer,
        );
        let mut hist = self.store.history(&pid)?;
        hist.push(change.clone());
        if !Policy::fold(&org_id, &hist)
            .accepted
            .contains(&change.change_id)
        {
            return Err(ClientError::NotAdmin(org.into()));
        }
        self.store.put(change.clone())?;
        self.refresh_policies()?;
        Ok(change)
    }
}
