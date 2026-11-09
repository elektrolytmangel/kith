//! Creating, editing, receiving and reading changes.

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    /// This device's ID.
    pub fn device_id(&self) -> DeviceId {
        self.key.device_id()
    }

    /// Create a new object with an initial payload, in the default scope: the org
    /// this device belongs to, or `local` (never synced) before it joins one. With
    /// several orgs use [`Self::create_in`]. Fails with [`ClientError::Forbidden`]
    /// if the org's policy does not let this device write objects of type `ty`.
    pub fn create(&mut self, ty: ObjectType, payload: Vec<u8>) -> Result<Change, ClientError> {
        let scope = self.default_scope()?;
        self.create_in(scope, ty, payload)
    }

    /// Create a new object in `scope` (an org this device belongs to, or `local`).
    pub fn create_in(
        &mut self,
        scope: Scope,
        ty: ObjectType,
        payload: Vec<u8>,
    ) -> Result<Change, ClientError> {
        if ty.as_str() == POLICY_TYPE {
            return Err(ClientError::Forbidden("use the policy methods".into()));
        }
        if snapshot::is_snapshot(&payload) {
            return Err(ClientError::Forbidden(
                "payloads starting with the snapshot marker are reserved".into(),
            ));
        }
        self.check_scope(&scope)?;
        self.commit(scope, ObjectId::random(), ty, vec![], payload)
    }

    /// The scope `create` uses: the only org this device is a member of, else `local`.
    pub fn default_scope(&self) -> Result<Scope, ClientError> {
        let mut orgs = self
            .orgs
            .0
            .iter()
            .filter(|(_, st)| st.chain.is_some())
            .map(|(o, _)| o);
        match (orgs.next(), orgs.next()) {
            (None, _) => Ok(Scope::local()),
            (Some(org), None) => {
                Ok(Scope::parse(org).map_err(|e| ClientError::Forbidden(e.to_string()))?)
            }
            _ => Err(ClientError::AmbiguousScope),
        }
    }

    /// `local`, or an org (or subgroup of one) this device is a member of.
    pub(crate) fn check_scope(&self, scope: &Scope) -> Result<(), ClientError> {
        if scope.subgroup_name().is_some() && !self.groups.is_member(scope.as_str()) {
            return Err(ClientError::Forbidden(format!(
                "not a member of subgroup {scope}"
            )));
        }
        match scope.org_id() {
            None => Ok(()),
            Some(org)
                if self
                    .orgs
                    .0
                    .get(&org.to_hex())
                    .is_some_and(|s| s.chain.is_some()) =>
            {
                Ok(())
            }
            Some(org) => Err(ClientError::Forbidden(format!("not a member of org {org}"))),
        }
    }

    /// Append a change to an existing object, building on its current heads.
    /// Never blocks on a lock: concurrent edits become a fork that the merge
    /// layer resolves (REQ-DATA-004).
    pub fn edit(&mut self, object: ObjectId, payload: Vec<u8>) -> Result<Change, ClientError> {
        let (ty, scope) = self.object_meta(&object)?;
        if ty.as_str() == POLICY_TYPE {
            return Err(ClientError::Forbidden("use the policy methods".into()));
        }
        if snapshot::is_snapshot(&payload) {
            return Err(ClientError::Forbidden(
                "payloads starting with the snapshot marker are reserved".into(),
            ));
        }
        let parents = self.valid_heads(&object)?;
        self.commit(scope, object, ty, parents, payload)
    }

    /// Type and scope of an object, from any change of it we still store (a creation
    /// change is always kept, see [`Self::compact`]).
    pub(crate) fn object_meta(
        &self,
        object: &ObjectId,
    ) -> Result<(ObjectType, Scope), ClientError> {
        self.store
            .history(object)?
            .into_iter()
            .find(|c| !self.invalid.contains(&c.change_id))
            .map(|c| (c.body.object_type, c.body.scope))
            .ok_or(ClientError::UnknownObject(*object))
    }

    /// Heads of an object among the changes the policy allows.
    pub(crate) fn valid_heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, ClientError> {
        let hist = self.merge_history(object)?;
        let mut heads: Vec<ChangeId> = hist.iter().map(|c| c.change_id).collect();
        for c in &hist {
            heads.retain(|h| !c.body.parents.contains(h));
        }
        heads.sort();
        Ok(heads)
    }

    /// Validate and store a change received from a peer.
    /// Returns `true` if it was new.
    /// A change with a bad hash or signature is refused. Every other change is
    /// stored, and the policy decides whether it counts (REQ-PERM-002): one the
    /// author was not allowed to make, or that builds on such a change, returns
    /// [`ClientError::Forbidden`] and is kept out of history, merging and new
    /// edits. It is still passed on in catch-up, so every device sees it and reaches
    /// the same verdict, and a later policy change (a late grant) can make it count.
    /// Policy changes trigger a re-check of everything stored.
    pub fn receive(&mut self, change: Change) -> Result<bool, ClientError> {
        change.verify()?;
        // Folded into a snapshot already (creations are always kept, ADR 0026).
        if self.covered.contains(&change.change_id) && !change.is_creation() {
            return Ok(false);
        }
        // Only orgs we belong to; an object never moves between scopes.
        self.check_scope(&change.body.scope)?;
        if let Some(first) = self.store.history(&change.body.object_id)?.first()
            && first.body.scope != change.body.scope
        {
            return Err(ClientError::Forbidden(
                "object belongs to another scope".into(),
            ));
        }
        // Parents are changes of the same object.
        for p in &change.body.parents {
            if let Some(parent) = self.store.get(p)?
                && parent.body.object_id != change.body.object_id
            {
                return Err(ClientError::Forbidden(format!(
                    "parent {p} belongs to another object"
                )));
            }
        }
        let full = self.quarantined.get(&change.author).copied().unwrap_or(0) >= MAX_QUARANTINE;
        if change.body.object_type.as_str() == POLICY_TYPE {
            // Policy changes by non-admins never count (members only link their own
            // devices). Once we have the org's policy, others are not kept (each
            // kept one re-folds the policy), except the root-signed genesis; before
            // that, up to the cap. A refused one comes again with the next catch-up.
            let org_id = change.body.scope.org_id();
            let policy = org_id
                .and_then(|o| self.policies.get(&o.to_hex()))
                .filter(|p| p.creator.is_some());
            let link = matches!(
                PolicyOp::decode(&change.body.payload),
                Ok(PolicyOp::LinkDevice { .. })
            );
            let admin = policy.is_some_and(|p| match p.role_of(&change.author) {
                Some(Role::Admin) => true,
                Some(_) => link,
                None => false,
            }) || org_id.is_some_and(|o| o == change.author);
            if (full || policy.is_some()) && !admin {
                return Err(ClientError::Forbidden(
                    "too many rejected changes from this device".into(),
                ));
            }
            let new = self.store.put(change)?;
            if new {
                self.refresh_policies()?;
            }
            return Ok(new);
        }
        if let Err(e) = self.check_allowed(&change) {
            // Kept (quarantined) so every device decides the same, up to a cap per
            // author so a misbehaving member cannot fill our storage (REQ-RELAY-006).
            if !full && self.store.put(change.clone())? {
                *self.quarantined.entry(change.author).or_default() += 1;
            }
            self.invalid.insert(change.change_id);
            return Err(e);
        }
        let new = self.store.put(change.clone())?;
        if new && snapshot::is_snapshot(&change.body.payload) {
            self.apply_snapshot(&change)?;
        }
        Ok(new)
    }

    pub(crate) fn check_allowed(&self, change: &Change) -> Result<(), ClientError> {
        if let Some(p) = change
            .body
            .parents
            .iter()
            .find(|p| self.invalid.contains(p))
        {
            return Err(ClientError::Forbidden(format!(
                "builds on rejected change {p}"
            )));
        }
        // The policy of the org the change belongs to.
        let org = change.body.scope.org_id().map(|o| o.to_hex());
        if snapshot::is_snapshot(&change.body.payload) {
            // Only admins fold history (ADR 0026); a snapshot an admin made before being
            // restricted stays valid like their other seen changes (`kept`).
            if org.is_none() || snapshot::Snapshot::decode(&change.body.payload).is_none() {
                return Err(ClientError::Forbidden("malformed snapshot".into()));
            }
            if let Some(policy) = org.as_ref().and_then(|o| self.policies.get(o))
                && policy.creator.is_some()
                && !policy.is_admin_device(&change.author)
                && !policy
                    .kept
                    .get(&change.author)
                    .is_some_and(|k| k.contains(&change.change_id))
            {
                return Err(ClientError::Forbidden(
                    "only admins may create snapshots".into(),
                ));
            }
        }
        if let Some(policy) = org.as_ref().and_then(|o| self.policies.get(o))
            && policy.creator.is_some()
            && !policy.allows(change)
        {
            return Err(ClientError::Forbidden(format!(
                "{} may not write {} in {}",
                change.author,
                change.body.object_type.as_str(),
                org.unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Re-fold every org's policy and re-check all stored changes against it.
    /// Called on start and whenever a policy change arrives (they are rare).
    pub(crate) fn refresh_policies(&mut self) -> Result<(), ClientError> {
        let mut policies = std::collections::BTreeMap::new();
        for org in self.orgs.0.keys() {
            let Ok(org_id) = DeviceId::from_hex(org) else {
                continue;
            };
            let hist = self.store.history(&policy_object_id(&org_id))?;
            if !hist.is_empty() {
                policies.insert(org.clone(), Policy::fold(&org_id, &hist));
            }
        }
        self.policies = policies;
        self.invalid.clear();
        self.quarantined.clear();
        if self.policies.is_empty() {
            return Ok(());
        }
        // Parents before children (per object), so a rejected parent rejects its children.
        let mut all = Vec::new();
        for id in self.store.all_ids()? {
            if let Some(c) = self.store.get(&id)? {
                all.push(c);
            }
        }
        all.sort_by_key(|c| (c.body.timestamp_ms, c.change_id));
        let mut changed = true;
        while changed {
            changed = false;
            for c in &all {
                if self.invalid.contains(&c.change_id) || c.body.object_type.as_str() == POLICY_TYPE
                {
                    continue;
                }
                if self.check_allowed(c).is_err() {
                    self.invalid.insert(c.change_id);
                    changed = true;
                }
            }
        }
        // Quarantine counts per author: rejected changes and policy changes that did not count.
        for c in &all {
            let rejected_policy = c.body.object_type.as_str() == POLICY_TYPE
                && !self
                    .policies
                    .values()
                    .any(|p| p.accepted.contains(&c.change_id));
            if self.invalid.contains(&c.change_id) || rejected_policy {
                *self.quarantined.entry(c.author).or_default() += 1;
            }
        }
        // Snapshots (re)apply: delete what they cover, also what an earlier run missed.
        self.covered.clear();
        for c in &all {
            if snapshot::is_snapshot(&c.body.payload) {
                self.apply_snapshot(c)?;
            }
        }
        Ok(())
    }

    /// The merged state of an object: all its changes, including concurrent
    /// forks, combined by `merger` (REQ-DATA-004). Does not change the store;
    /// the next `edit` names all current heads as parents, which joins forks.
    pub fn materialize<M: Merger>(
        &self,
        object: &ObjectId,
        merger: &M,
    ) -> Result<Materialized<M::State>, ClientError> {
        let hist = self.merge_history(object)?;
        if hist.is_empty() {
            return Err(ClientError::UnknownObject(*object));
        }
        Ok(merger.materialize(&hist)?)
    }

    /// Change history of an object: the changes the policy allows. Changes folded
    /// into a snapshot are gone (REQ-DATA-005); snapshots themselves are not listed.
    pub fn history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        let mut h = self.merge_history(object)?;
        h.retain(|c| !snapshot::is_snapshot(&c.body.payload));
        Ok(h)
    }

    /// Like [`Self::history`], but with the object's snapshots: what a [`Merger`]
    /// needs, because a snapshot carries the payloads of the changes it covers.
    pub(crate) fn merge_history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        let mut h = self.store.history(object)?;
        h.retain(|c| !self.invalid.contains(&c.change_id) && !self.covered.contains(&c.change_id));
        Ok(h)
    }

    /// The objects this device knows, as their creation changes (object ID, type, scope,
    /// author, creation time), oldest first; optionally only one `object_type`. Includes
    /// documents and file objects, not the internal policy object. Walks the whole store,
    /// so call it when building a list, not per frame.
    pub fn objects(&self, object_type: Option<&str>) -> Result<Vec<Change>, ClientError> {
        let mut out = Vec::new();
        for id in self.store.all_ids()? {
            let Some(c) = self.store.get(&id)? else {
                continue;
            };
            let ty = c.body.object_type.as_str();
            if c.is_creation()
                && ty != POLICY_TYPE
                && object_type.is_none_or(|t| t == ty)
                && !self.invalid.contains(&c.change_id)
            {
                out.push(c);
            }
        }
        out.sort_by_key(|c| (c.body.timestamp_ms, *c.change_id.as_bytes()));
        Ok(out)
    }
}
