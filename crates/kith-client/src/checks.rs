//! Checks on incoming MLS commits, Welcomes and claims; fork handling.

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    /// Is `device` (hex) in our view of `group` and not excluded by `org`'s policy?
    pub(crate) fn trusted_member(&self, org: &str, group: &str, device: &str) -> bool {
        let Ok(d) = DeviceId::from_hex(device) else {
            return false;
        };
        self.groups.members(group).is_ok_and(|m| m.contains(&d))
            && self
                .policies
                .get(org)
                .filter(|p| p.creator.is_some())
                .is_none_or(|p| p.role_of(&d).is_some())
    }

    /// What a commit in `group` (of `org`) may change (ADR 0017). With a policy:
    /// in the org's group, admins add and remove devices, a member may add a device
    /// linked to it, and any member may re-add a device that is already in the
    /// group; revoked devices are never added. In a subgroup only its owner adds,
    /// re-adds and removes, and only listed devices are added. Key updates are
    /// always allowed. Without a policy everything is allowed.
    pub(crate) fn commit_check(
        &self,
        org: &str,
        group: &str,
    ) -> impl FnOnce(&kith_crypto::CommitInfo) -> Result<(), String> + use<S, K> {
        let policy = self
            .policies
            .get(org)
            .filter(|p| p.creator.is_some())
            .cloned();
        let subgroup = group
            .strip_prefix(org)
            .and_then(|g| g.strip_prefix('/'))
            .map(str::to_string);
        move |c| {
            let Some(p) = policy else {
                return Ok(());
            };
            let by = c.committer;
            let readded = |d: &DeviceId| c.added.contains(d) && c.removed.contains(d);
            if let Some(d) = c.added.iter().find(|d| p.revoked.contains(d)) {
                return Err(format!("{d} is revoked"));
            }
            match subgroup {
                None => {
                    let admin = p.role_of(&by) == Some(Role::Admin);
                    if p.role_of(&by).is_none() {
                        return Err(format!("{by} has no role"));
                    }
                    for d in &c.added {
                        if !(admin || readded(d) || p.links.get(d) == Some(&by)) {
                            return Err(format!("{by} may not add {d}"));
                        }
                    }
                    for d in &c.removed {
                        if !(admin || readded(d)) {
                            return Err(format!("{by} may not remove {d}"));
                        }
                    }
                }
                Some(name) => {
                    let changes = !c.added.is_empty() || !c.removed.is_empty();
                    if changes && p.subgroup_owners.get(&name) != Some(&by) {
                        return Err("only the subgroup's owner changes its members".into());
                    }
                    let listed = p.subgroup(&name);
                    if let Some(d) = c
                        .added
                        .iter()
                        .find(|d| !listed.is_some_and(|l| l.contains(d)))
                    {
                        return Err(format!("{d} is not in the subgroup"));
                    }
                }
            }
            Ok(())
        }
    }

    /// The checks a Welcome delivered in `org` by `from` must pass before we join
    /// (ADR 0016). We join only a group we asked to be added to, from the device we
    /// asked; or, the first time, the org's group from the device that issued our
    /// membership certificate (`chain`). Every device in the new group must be one
    /// we accept as a member.
    /// Check the admin's answer to our claim and derive the short code. The signer
    /// must be an admin of the org (or the issuing member of an own-device invite);
    /// from then on only its Welcome is accepted.
    pub(crate) fn claim_code(
        &mut self,
        org: &str,
        from: &str,
        token: [u8; 16],
        nonce: &[u8; 32],
        signature: &[u8; 64],
        chain: &str,
    ) -> Result<String, String> {
        let (invite, kp) = self
            .claiming
            .get(org)
            .filter(|(i, _)| i.token == token)
            .ok_or("no claim of ours for this invite")?;
        let signer = DeviceId::from_hex(from).map_err(|e| e.to_string())?;
        let proven = CertChain::from_hex(chain)
            .and_then(|c| c.verify(&invite.org, &signer))
            .map_err(|e| format!("answer to our claim: {e}"))?;
        let allowed = match invite.own_device {
            Some(issuer) => issuer == signer,
            None => proven.admin,
        };
        if !allowed {
            return Err("answer to our claim not from an admin or the invite's issuer".into());
        }
        kith_core::verify_signature(&signer, &invite.nonce_signed_bytes(kp, nonce), signature)
            .map_err(|_| "answer to our claim: bad signature".to_string())?;
        let code = invite.short_code(kp, nonce);
        self.joining.insert(org.into(), Some(signer));
        Ok(code)
    }

    pub(crate) fn welcome_check(
        &self,
        org: &str,
        from: &str,
        chain: &str,
    ) -> impl FnOnce(&kith_crypto::WelcomeInfo) -> Result<(), String> + use<S, K> {
        let org = org.to_string();
        let from = DeviceId::from_hex(from).ok();
        let me = self.device_id();
        let asked = self.welcome_from.clone();
        let first_join = !self.groups.has_group(&org) && self.chain(&org).is_none();
        let joining = self.joining.get(&org).copied();
        let policy = self
            .policies
            .get(&org)
            .filter(|p| p.creator.is_some())
            .cloned();
        let current = self.groups.members(&org).unwrap_or_default();
        let chain = chain.to_string();
        move |w| {
            let adder = w.adder.ok_or("Welcome without an adder")?;
            if Some(adder) != from {
                return Err("Welcome not signed by its sender".into());
            }
            if !in_org(&org, &w.group) {
                return Err("Welcome for a group of another org".into());
            }
            if asked.get(&w.group) == Some(&adder) {
                let Some(p) = policy else {
                    return Ok(());
                };
                if w.group == org {
                    // Members the policy names, or that our group already had.
                    if let Some(m) = w.members.iter().find(|m| {
                        p.role_of(m).is_none() && (p.revoked.contains(m) || !current.contains(m))
                    }) {
                        return Err(format!("{m} in the new group is not a member"));
                    }
                } else {
                    let name = &w.group[org.len() + 1..];
                    if p.subgroup_owners.get(name) != Some(&adder) {
                        return Err("Welcome not from the subgroup's owner".into());
                    }
                    let listed = p.subgroup(name);
                    if let Some(m) = w
                        .members
                        .iter()
                        .find(|m| !listed.is_some_and(|l| l.contains(m)))
                    {
                        return Err(format!("{m} is not in the subgroup"));
                    }
                }
                return Ok(());
            }
            if w.group == org && first_join && !w.replaces {
                // Our first join: the adder issued the certificate it sends us,
                // under the org root key.
                let org_id = DeviceId::from_hex(&org).map_err(|e| e.to_string())?;
                let chain = CertChain::from_hex(&chain).map_err(|e| e.to_string())?;
                chain.verify(&org_id, &me).map_err(|e| e.to_string())?;
                if chain.leaf().map(|l| l.issuer) != Some(adder) {
                    return Err("Welcome not from the certificate's issuer".into());
                }
                if let Some(Some(issuer)) = joining
                    && issuer != adder
                {
                    return Err("Welcome not from the device that answered our claim".into());
                }
                return Ok(());
            }
            Err("unexpected Welcome".into())
        }
    }

    /// The group forked between us and `peer` (ADR 0004).
    pub(crate) fn on_fork(
        &mut self,
        org: String,
        group: String,
        peer: String,
        we_win: bool,
    ) -> Result<Handled, ClientError> {
        let mut replies = vec![];
        if we_win {
            // Show the peer the commit we followed: it then sees it lost.
            if let Some(c) = self.groups.last_commit(&group) {
                replies.push(direct(
                    &org,
                    &peer,
                    sync::outer_body(&Outer::Commits {
                        group: group.clone(),
                        commits: vec![(c.committer, c.commit)],
                    }),
                ));
            }
        } else {
            let epoch = self.groups.epoch(&group)?;
            if self.readd_asked.get(&group) != Some(&epoch) {
                self.readd_asked.insert(group.clone(), epoch);
                replies.push(self.readd_request_frame(&org, &group, &peer)?);
            }
        }
        Ok(Handled {
            event: Event::Fork {
                org: group,
                peer,
                we_win,
            },
            replies,
        })
    }

    /// We are behind on `group`: ask `from` for the commits since `local`.
    pub(crate) fn behind(&self, org: String, group: String, from: String, local: u64) -> Handled {
        Handled {
            replies: vec![direct(
                &org,
                &from,
                sync::outer_body(&Outer::CommitRequest {
                    group: group.clone(),
                    epoch: local,
                }),
            )],
            event: Event::EpochBehind { org: group, from },
        }
    }

    /// The group (org or `org/subgroup` key) of an MLS message delivered for `org`;
    /// `None` if it is for another org, [`SUBGROUP_NOT_OURS`] for a subgroup of this
    /// org that we are not in.
    pub(crate) fn group_in(&self, org: &str, mls_message: &[u8]) -> Option<String> {
        let g = Groups::message_group(mls_message).ok()?;
        if !in_org(org, &g) {
            return None;
        }
        if g != org && !self.groups.has_group(&g) {
            return Some(SUBGROUP_NOT_OURS.into());
        }
        Some(g)
    }

    /// Send `to` the commits since `epoch`, or ask it to be re-added. Starts one
    /// epoch earlier when the log has it, so the peer can tell whether it followed
    /// the same commit out of its previous epoch (fork detection).
    pub(crate) fn serve_commits(
        &self,
        org: String,
        group: String,
        to: String,
        epoch: u64,
    ) -> Result<Handled, ClientError> {
        let since = match epoch.checked_sub(1) {
            Some(prev) if matches!(self.groups.commits_since(&group, prev), Ok(Some(_))) => prev,
            _ => epoch,
        };
        let (bodies, commits, readd_needed) = match self.groups.commits_since(&group, since) {
            Ok(Some(cs)) => {
                let n = cs.len();
                (sync::commits_bodies(&group, cs), n, false)
            }
            Ok(None) => (
                vec![sync::outer_body(&Outer::ReaddNeeded {
                    group: group.clone(),
                })],
                0,
                true,
            ),
            Err(e) => {
                return Ok(Handled::event(Event::Rejected {
                    org,
                    from: to,
                    reason: e.to_string(),
                }));
            }
        };
        Ok(Handled {
            replies: bodies.into_iter().map(|b| direct(&org, &to, b)).collect(),
            event: Event::CommitsServed {
                org: group,
                to,
                commits,
                readd_needed,
            },
        })
    }
}
