//! Incoming relay frames: `handle_frame` and `handle_deliver`.

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    /// Handle a frame from the relay: decrypt it, validate and store peers'
    /// changes (REQ-SYNC-004), serve catch-up requests and absorb offers
    /// (REQ-SYNC-001..003), apply MLS commits and Welcomes and catch up on missed
    /// commits (REQ-ENC-001..004). Send `Handled::replies` to the relay.
    ///
    /// A bad message from a peer is reported as [`Event::Rejected`], not as an
    /// error, so a misbehaving device cannot break the receive loop. Only local
    /// failures (storage, MLS state) return `Err`.
    pub fn handle_frame(&mut self, frame: Frame) -> Result<Handled, ClientError> {
        let handled = match frame {
            Frame::Deliver { org, from, body } => {
                let mut h = self.handle_deliver(org, from, &body, false)?;
                h.replies.extend(self.subgroup_tasks()?);
                h
            }
            Frame::ClaimDeliver { org, from, body } => {
                self.handle_deliver(org, from, &body, true)?
            }
            Frame::Presence { org, online } => {
                let replies = self.rejoin_if_needed(&org, &online)?;
                Handled {
                    replies,
                    event: Event::Presence { org, online },
                }
            }
            Frame::Receipt { delivered } => Handled::event(Event::Receipt { delivered }),
            Frame::Error { code, message } => Handled::event(Event::RelayError { code, message }),
            _ => return Ok(Handled::event(Event::Ignored)),
        };
        // Decrypting advances ratchets and replies are encrypted: save before any
        // reply is sent.
        self.save_groups()?;
        Ok(handled)
    }

    /// `claim`: it came as a [`Frame::ClaimDeliver`], from a device that may not be
    /// a member. Only claims are taken from it, and claims only from it.
    pub(crate) fn handle_deliver(
        &mut self,
        org: String,
        from: String,
        body: &[u8],
        claim: bool,
    ) -> Result<Handled, ClientError> {
        let rejected = |reason: String| {
            Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            })
        };
        let outer = match sync::parse_outer(body) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        if claim != matches!(outer, Outer::Claim { .. }) {
            return Ok(rejected(if claim {
                "only an invite claim can come from a claiming device".into()
            } else {
                "an invite claim must come as a claim".into()
            }));
        }
        match outer {
            Outer::App(ct) => {
                let Some(group) = self.group_in(&org, &ct) else {
                    return Ok(rejected("message for another org".into()));
                };
                if group == SUBGROUP_NOT_OURS {
                    // Subgroup traffic we are not part of: reaches all of the org.
                    return Ok(Handled::event(Event::Ignored));
                }
                self.handle_app(org, group, from, &ct)
            }
            Outer::Commit(commit) => {
                let Some(group) = self.group_in(&org, &commit) else {
                    return Ok(rejected("commit for another org".into()));
                };
                if group == SUBGROUP_NOT_OURS {
                    return Ok(Handled::event(Event::Ignored));
                }
                // A broadcast commit comes from its committer.
                let Ok(committer) = DeviceId::from_hex(&from) else {
                    return Ok(rejected("sender is not a device ID".into()));
                };
                let check = self.commit_check(&org, &group);
                match self
                    .groups
                    .apply_commit_checked(&group, &commit, committer, check)
                {
                    Ok(CommitOutcome::Applied { epoch, removed }) => {
                        Ok(Handled::event(Event::GroupChanged {
                            org: group,
                            epoch,
                            removed,
                        }))
                    }
                    Ok(CommitOutcome::Stale) => Ok(Handled::event(Event::Ignored)),
                    // A fork we cannot verify (the epoch is gone): only a member we
                    // trust makes us ask to be re-added.
                    Ok(CommitOutcome::Fork { .. }) if !self.trusted_member(&org, &group, &from) => {
                        Ok(rejected("fork claimed by a non-member".into()))
                    }
                    Ok(CommitOutcome::Fork { we_win, .. }) => {
                        self.on_fork(org, group, from, we_win)
                    }
                    Err(GroupError::EpochGap { local, .. }) => {
                        Ok(self.behind(org, group, from, local))
                    }
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::Welcome { welcome, chain } => {
                let check = self.welcome_check(&org, &from, &chain);
                let joined = match self.groups.join_checked(&welcome, check) {
                    Ok(o) => o,
                    Err(e) => return Ok(rejected(e.to_string())),
                };
                self.welcome_from.remove(&joined);
                if joined == org {
                    self.joining.remove(&org);
                    self.claiming.remove(&org);
                }
                self.readd_asked.remove(&joined);
                if joined.contains('/') {
                    // A subgroup: fetch its history from the owner that added us.
                    self.kp_asked.remove(&joined);
                    let body = self.start_reconcile(&joined, Some(&from))?;
                    return Ok(Handled {
                        event: Event::Joined {
                            org: joined.clone(),
                        },
                        replies: vec![direct(&org, &from, body)],
                    });
                }
                if !chain.is_empty() {
                    if let Err(e) = self.adopt_chain(&joined, &chain) {
                        return Ok(rejected(format!("membership certificate: {e}")));
                    }
                    self.save_orgs()?;
                }
                // Announce with the certificate (we were pending), then ask a peer
                // for the history.
                let body = self.start_reconcile(&joined, None)?;
                Ok(Handled {
                    event: Event::Joined {
                        org: joined.clone(),
                    },
                    replies: vec![
                        self.announce_frame(&joined),
                        Frame::SyncRequest { org: joined, body },
                    ],
                })
            }
            Outer::Claim {
                token,
                proof,
                key_package,
            } => {
                let Some(invite) = self
                    .orgs
                    .0
                    .get(&org)
                    .and_then(|s| s.invites.iter().find(|i| i.token == token))
                    .cloned()
                else {
                    // Every admin of the org gets the claim; only the issuer knows it.
                    return Ok(Handled::event(Event::Ignored));
                };
                if invite.is_expired(now_ms()) {
                    return Ok(rejected("invite expired".into()));
                }
                if !invite.verify_claim(&key_package, &proof) {
                    return Ok(rejected("invite proof does not match".into()));
                }
                match self.groups.key_package_device(&key_package) {
                    Ok(d) if d.to_hex() == from => {}
                    _ => return Ok(rejected("KeyPackage is not the sender's".into())),
                }
                let key = (org.clone(), from.clone());
                let pending = self.claims.values().filter(|c| c.1 == token).count();
                if !self.claims.contains_key(&key) && pending >= MAX_CLAIMS_PER_INVITE {
                    return Ok(rejected("too many claims for this invite".into()));
                }
                // A repeated claim with the same KeyPackage keeps its nonce (and code).
                let nonce = match self.claims.get(&key) {
                    Some((kp, t, n)) if *kp == key_package && *t == token => *n,
                    _ => kith_core::random_bytes(),
                };
                let code = invite.short_code(&key_package, &nonce);
                let answer = sync::outer_body(&Outer::ClaimNonce {
                    token,
                    nonce,
                    signature: self
                        .key
                        .sign(&invite.nonce_signed_bytes(&key_package, &nonce)),
                    chain: self.chain(&org).map(CertChain::to_hex).unwrap_or_default(),
                });
                self.claims.insert(key, (key_package, token, nonce));
                Ok(Handled {
                    replies: vec![direct(&org, &from, answer)],
                    event: Event::InviteClaimed { org, from, code },
                })
            }
            Outer::ClaimNonce {
                token,
                nonce,
                signature,
                chain,
            } => Ok(
                match self.claim_code(&org, &from, token, &nonce, &signature, &chain) {
                    Ok(code) => Handled::event(Event::ClaimCode { org, from, code }),
                    Err(e) => rejected(e),
                },
            ),
            Outer::Cert(chain) if !self.is_newer_chain(&org, &chain) => {
                Ok(rejected("membership certificate: older than ours".into()))
            }
            Outer::Cert(chain) => match self.adopt_chain(&org, &chain) {
                Ok(admin) => {
                    self.save_orgs()?;
                    Ok(Handled {
                        replies: vec![self.announce_frame(&org)],
                        event: Event::CertificateUpdated { org, admin },
                    })
                }
                Err(e) => Ok(rejected(format!("membership certificate: {e}"))),
            },
            Outer::KeyPackage { group, key_package } if group != org => {
                if !in_org(&org, &group) {
                    return Ok(rejected("group of another org".into()));
                }
                self.subgroup_key_package(org, group, from, &key_package)
            }
            Outer::KeyPackage {
                key_package: kp, ..
            } => {
                if !self.trusted_member(&org, &org, &from) {
                    return Ok(rejected("not a member: join with an invite".into()));
                }
                // A member that lost the group (REQ-ENC-004). Only for its own key,
                // checked before the group changes.
                if !self
                    .groups
                    .key_package_device(&kp)
                    .is_ok_and(|d| d.to_hex() == from)
                {
                    return Ok(rejected("KeyPackage is not the sender's".into()));
                }
                match self.groups.readd_member(&self.key, &org, &kp) {
                    Ok(added) => Ok(Handled {
                        replies: self.readded_frames(&org, added),
                        event: Event::MemberReAdded { org, device: from },
                    }),
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::CommitRequest { group, .. }
            | Outer::Commits { group, .. }
            | Outer::ReaddNeeded { group }
                if !in_org(&org, &group) =>
            {
                Ok(rejected("group of another org".into()))
            }
            Outer::CommitRequest { group, epoch } => {
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                Ok(self.serve_commits(org, group, from, epoch)?)
            }
            Outer::Commits { group, commits } => {
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                let mut applied = 0;
                for (committer, c) in &commits {
                    let check = self.commit_check(&org, &group);
                    match self
                        .groups
                        .apply_commit_checked(&group, c, *committer, check)
                    {
                        Ok(CommitOutcome::Applied { .. }) => applied += 1,
                        Ok(CommitOutcome::Stale) => {}
                        // The rest of the batch belongs to the other branch.
                        Ok(CommitOutcome::Fork { we_win, .. }) => {
                            return self.on_fork(org, group, from, we_win);
                        }
                        Err(e) => return Ok(rejected(e.to_string())),
                    }
                }
                let epoch = self.groups.epoch(&group)?;
                // Data sent while we were behind could not be read: resync with this peer.
                let replies = if applied > 0 && self.groups.is_member(&group) {
                    vec![direct(
                        &org,
                        &from,
                        self.start_reconcile(&group, Some(&from))?,
                    )]
                } else {
                    vec![]
                };
                Ok(Handled {
                    event: Event::CommitsApplied {
                        org: group,
                        from,
                        applied,
                        epoch,
                    },
                    replies,
                })
            }
            Outer::ReaddNeeded { group } => {
                // Only a group we have can be re-joined, and only a member of it,
                // that the policy does not exclude, can tell us to.
                if self.groups.epoch(&group).is_err() {
                    return Ok(rejected("not in this group".into()));
                }
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                let frame = self.readd_request_frame(&org, &group, &from)?;
                Ok(Handled {
                    event: Event::ReAddRequested { org: group, from },
                    replies: vec![frame],
                })
            }
        }
    }
}
