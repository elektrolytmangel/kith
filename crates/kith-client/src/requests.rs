//! Outgoing sync and broadcast frames, subgroup tasks.

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    // ---- data sync ----

    /// Frame that broadcasts a new change, encrypted for `org`'s group, to the
    /// other online devices (REQ-SYNC-004).
    pub fn broadcast_frame(&mut self, org: &str, change: &Change) -> Result<Frame, ClientError> {
        if !in_org(org, change.body.scope.as_str()) {
            return Err(ClientError::Forbidden(format!(
                "change belongs to scope {}, not org {org}",
                change.body.scope
            )));
        }
        // Encrypted for the scope's group: subgroup data only its members can read.
        let body = self.app_body(change.body.scope.as_str(), &sync::change_body(change))?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body,
        })
    }

    /// The request that starts catch-up (REQ-SYNC-001..003): send it to the relay,
    /// which hands it to one online peer. The two reconcile their sets of changes
    /// in a few rounds (traffic grows with the difference, not the history), then
    /// each sends what the other lacks: [`Event::SyncCompared`], then
    /// [`Event::SyncReceived`]. Works from an empty store (join). The relay's
    /// `Receipt` shows whether a peer was online (`delivered` empty: try later).
    pub fn sync_request_frame(&mut self, org: &str) -> Result<Frame, ClientError> {
        let body = self.start_reconcile(org, None)?;
        self.save_groups()?;
        Ok(Frame::SyncRequest {
            org: org.into(),
            body,
        })
    }

    /// Start (or restart) our reconciliation for `scope` (an org or `org/subgroup`
    /// key); returns the first query, encrypted for that scope's group.
    /// `peer`: the device the query goes to (`Direct`), or `None` for a
    /// `SyncRequest` (the relay picks one).
    pub(crate) fn start_reconcile(
        &mut self,
        scope: &str,
        peer: Option<&str>,
    ) -> Result<Vec<u8>, ClientError> {
        let ids = self.store.scope_ids(&org_scope(scope)?)?;
        let (r, first) = kith_sync::Reconciliation::start(&ids)?;
        let body = self.app_body(scope, &sync::query_body(&first))?;
        self.reconciling
            .insert(scope.into(), (r, peer.map(str::to_string)));
        Ok(body)
    }

    /// Catch-up requests for `org` and for each of its subgroups this device is in
    /// (those go `direct` to a subgroup member: the relay does not know them), plus
    /// any pending subgroup membership messages.
    pub fn sync_request_frames(&mut self, org: &str) -> Result<Vec<Frame>, ClientError> {
        let mut frames = vec![self.sync_request_frame(org)?];
        let me = self.device_id();
        let subs: Vec<String> = self
            .groups
            .orgs()
            .into_iter()
            .filter(|g| in_org(org, g) && g.as_str() != org && self.groups.is_member(g))
            .collect();
        for g in subs {
            let owner = self.subgroup_owner(org, &g);
            let peer = owner
                .filter(|o| *o != me)
                .or_else(|| self.groups.members(&g).ok()?.into_iter().find(|d| *d != me));
            if let Some(peer) = peer {
                let peer = peer.to_hex();
                let body = self.start_reconcile(&g, Some(&peer))?;
                frames.push(direct(org, &peer, body));
            }
        }
        self.kp_asked.retain(|g| !in_org(org, g));
        frames.extend(self.subgroup_tasks()?);
        self.save_groups()?;
        Ok(frames)
    }

    pub(crate) fn subgroup_owner(&self, org: &str, group: &str) -> Option<DeviceId> {
        let name = group.strip_prefix(org)?.strip_prefix('/')?;
        self.policies.get(org)?.subgroup_owners.get(name).copied()
    }

    /// Bring MLS subgroups in line with the policy (6b-2): the owner creates the
    /// group and removes devices the policy no longer lists; a listed member that is
    /// not in the group yet sends the owner a KeyPackage.
    pub(crate) fn subgroup_tasks(&mut self) -> Result<Vec<Frame>, ClientError> {
        let me = self.device_id();
        let mut frames = vec![];
        let mut wanted: Vec<(
            String,
            String,
            std::collections::BTreeSet<DeviceId>,
            DeviceId,
        )> = vec![];
        for (org, policy) in &self.policies {
            for (name, members) in &policy.subgroups {
                if let Some(owner) = policy.subgroup_owners.get(name) {
                    wanted.push((
                        org.clone(),
                        format!("{org}/{name}"),
                        members.clone(),
                        *owner,
                    ));
                }
            }
        }
        for (org, key, members, owner) in wanted {
            if owner == me {
                if !self.groups.has_group(&key) {
                    self.groups.create_group(&self.key, &key)?;
                }
                let stale: Vec<DeviceId> = self
                    .groups
                    .members(&key)?
                    .into_iter()
                    .filter(|d| *d != me && !members.contains(d))
                    .collect();
                for d in stale {
                    let commit = self.groups.remove_member(&self.key, &key, d)?;
                    frames.push(Frame::Broadcast {
                        org: org.clone(),
                        body: sync::outer_body(&Outer::Commit(commit)),
                    });
                }
            } else if members.contains(&me)
                && !self.groups.is_member(&key)
                && self.kp_asked.insert(key.clone())
            {
                frames.push(self.readd_request_frame(&org, &key, &owner.to_hex())?);
            }
        }
        if !frames.is_empty() {
            self.save_groups()?;
        }
        Ok(frames)
    }

    /// The owner's side of a member's KeyPackage for subgroup `group` (`org/name`).
    pub(crate) fn subgroup_key_package(
        &mut self,
        org: String,
        group: String,
        from: String,
        key_package: &[u8],
    ) -> Result<Handled, ClientError> {
        let rejected = |reason: &str| {
            Ok(Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason: reason.into(),
            }))
        };
        let me = self.device_id();
        let Some(name) = group.strip_prefix(&org).and_then(|g| g.strip_prefix('/')) else {
            return rejected("not a subgroup of this org");
        };
        let Some(policy) = self.policies.get(&org) else {
            return rejected("no policy");
        };
        if policy.subgroup_owners.get(name) != Some(&me) {
            return Ok(Handled::event(Event::Ignored));
        }
        let listed = DeviceId::from_hex(&from)
            .ok()
            .is_some_and(|d| policy.subgroup(name).is_some_and(|m| m.contains(&d)));
        if !listed {
            return rejected("not a member of this subgroup in the policy");
        }
        if !self
            .groups
            .key_package_device(key_package)
            .is_ok_and(|d| d.to_hex() == from)
        {
            return rejected("KeyPackage is not the sender's");
        }
        let already = self
            .groups
            .members(&group)
            .is_ok_and(|m| m.iter().any(|d| d.to_hex() == from));
        let added = if already {
            self.groups.readd_member(&self.key, &group, key_package)
        } else {
            self.groups.add_member(&self.key, &group, key_package)
        };
        let added = match added {
            Ok(a) if a.member.to_hex() == from => a,
            Ok(_) => return rejected("KeyPackage is not the sender's"),
            Err(e) => return rejected(&e.to_string()),
        };
        self.save_groups()?;
        Ok(Handled {
            replies: self.readded_frames(&org, added),
            event: if already {
                Event::MemberReAdded {
                    org: group,
                    device: from,
                }
            } else {
                Event::MemberAdded {
                    org: group,
                    device: from,
                }
            },
        })
    }

    /// Encrypt an inner message as an outer `App` body. The caller saves the
    /// MLS state before the body leaves the device.
    pub(crate) fn app_body(&mut self, org: &str, inner: &[u8]) -> Result<Vec<u8>, ClientError> {
        let ct = self.groups.encrypt(&self.key, org, inner)?;
        Ok(sync::outer_body(&Outer::App(ct)))
    }

    pub(crate) fn save_groups(&mut self) -> Result<(), ClientError> {
        let sealed = sealed::seal(&self.storage_key, MLS_STATE_KEY, &self.groups.to_bytes());
        Ok(self.store.put_meta(MLS_STATE_KEY, &sealed)?)
    }
}
