//! Organizations, certificates and invitations (phase 5, ADR 0005).

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    // ---- organizations and invitations (phase 5, ADR 0005) ----

    /// Create an organization: a new root key, whose public key is the org ID
    /// (returned, hex), its MLS group with this device as the only member, and a
    /// root-signed admin certificate for this device. The root key is kept in the
    /// store; only this device can make other admins ([`Self::grant_admin`]).
    pub fn create_org(&mut self) -> Result<String, ClientError> {
        self.create_org_with_root_key(&DeviceKey::generate().secret_bytes())
    }

    /// [`Self::create_org`] with a given root key secret, for apps that keep the
    /// root key elsewhere (e.g. a recovery backup). Fails if the org exists here.
    pub fn create_org_with_root_key(
        &mut self,
        root_secret: &[u8; 32],
    ) -> Result<String, ClientError> {
        let root = DeviceKey::from_secret_bytes(root_secret);
        let org_id = root.device_id();
        let org = org_id.to_hex();
        self.groups.create_group(&self.key, &org)?;
        let cert = MembershipCert::issue(&root, org_id, self.device_id(), true, now_ms());
        self.orgs.0.insert(
            org.clone(),
            org::OrgState {
                chain: Some(CertChain(vec![cert])),
                root: Some(*root_secret),
                invites: vec![],
            },
        );
        self.save_groups()?;
        self.save_orgs()?;
        // The policy object starts with our root-signed admin certificate, in a
        // change signed by the root key itself (no other admin can make one).
        let genesis = PolicyOp::Genesis {
            admin: MembershipCert::issue(&root, org_id, self.device_id(), true, now_ms()),
        };
        self.policy_commit_by(&org, genesis, Some(&root))?;
        Ok(org)
    }

    /// This device's membership proof for `org` (hex), empty if it has none yet.
    pub fn membership_proof(&self, org: &str) -> String {
        self.chain(org).map(CertChain::to_hex).unwrap_or_default()
    }

    /// True if this device may invite and admit devices to `org`.
    pub fn is_admin(&self, org: &str) -> bool {
        self.chain(org)
            .and_then(CertChain::leaf)
            .is_some_and(|c| c.admin)
    }

    pub(crate) fn chain(&self, org: &str) -> Option<&CertChain> {
        self.orgs.0.get(org).and_then(|s| s.chain.as_ref())
    }

    /// Frame announcing `org` to the relay with this device's membership proof.
    /// Without a proof (joining) the relay treats the device as pending.
    pub fn announce_frame(&self, org: &str) -> Frame {
        Frame::Announce {
            orgs: vec![kith_protocol::Membership {
                org: org.into(),
                proof: self.membership_proof(org),
                always_on: self.always_on,
                revoked: self
                    .revocations
                    .iter()
                    .filter(|r| r.org.to_hex() == org)
                    .map(Revocation::to_hex)
                    .collect(),
            }],
        }
    }

    /// Announce this device as an always-on client (a headless member that stays
    /// online): the relay then prefers it as catch-up partner (REQ-SYNC-006).
    pub fn set_always_on(&mut self, on: bool) {
        self.always_on = on;
    }

    /// The frames to send in answer to a relay's `challenge`: the signature that
    /// proves device ownership, then the announcement of `org`. `None` for any
    /// other frame.
    pub fn handshake_reply(&self, org: &str, frame: &Frame) -> Option<Vec<Frame>> {
        match frame {
            // Pipelined: a failed auth makes the relay send an error and close.
            Frame::Challenge { nonce } => {
                Some(vec![auth_frame(&self.key, nonce), self.announce_frame(org)])
            }
            _ => None,
        }
    }

    /// A one-time invite to `org`, valid for `ttl_ms` (REQ-INV-001). Returns the
    /// link to share (QR code, message). Only admins can invite; only this device
    /// can admit the claimer, so keep it online until then.
    pub fn create_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
    ) -> Result<String, ClientError> {
        if !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        self.issue_invite(org, relay, ttl_ms, 1)
    }

    /// A link that admits up to `max_uses` devices (REQ-INV-005, 1 to
    /// [`kith_core::membership::MAX_INVITE_USES`]), for example one link in a group
    /// chat. Everyone with the link can claim it, so the admin still sees each
    /// claim ([`Event::InviteClaimed`]) and decides with [`Self::accept_claim`] or
    /// [`Self::reject_claim`]; every admission uses one of the `max_uses`. The
    /// invite ends at its expiry or when the last use is taken. Admins only; this
    /// device must be online to admit.
    pub fn create_multi_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
        max_uses: u32,
    ) -> Result<String, ClientError> {
        if !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        if !(1..=kith_core::membership::MAX_INVITE_USES).contains(&max_uses) {
            return Err(ClientError::InvalidInvite(format!(
                "uses must be 1 to {}",
                kith_core::membership::MAX_INVITE_USES
            )));
        }
        self.issue_invite(org, relay, ttl_ms, max_uses)
    }

    pub(crate) fn issue_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
        uses: u32,
    ) -> Result<String, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        let invite = Invite::new_multi_use(org_id, relay, now_ms().saturating_add(ttl_ms), uses);
        let link = invite.to_link();
        self.orgs
            .0
            .entry(org.into())
            .or_default()
            .invites
            .push(invite);
        self.save_orgs()?;
        Ok(link)
    }

    /// A one-time link to add another device of *this user* to `org` (REQ-ID-002,
    /// ADR 0011). Any member can make one, not only admins. The new device gets this
    /// device's role (at most editor) and a certificate signed by this device; keep
    /// this device online until it is accepted ([`Self::accept_claim`]). Not
    /// available on a device that was itself added this way.
    pub fn create_own_device_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
    ) -> Result<String, ClientError> {
        let linkable = self
            .chain(org)
            .is_some_and(|c| c.leaf().is_some_and(|l| !l.own))
            && self.role_of(org, &self.device_id().to_hex())?.is_some();
        if !linkable {
            return Err(ClientError::Forbidden(
                "only a member that was not itself linked can add its own devices".into(),
            ));
        }
        let org_id = DeviceId::from_hex(org)?;
        let invite = Invite::new_own_device(
            org_id,
            relay,
            now_ms().saturating_add(ttl_ms),
            self.device_id(),
        );
        let link = invite.to_link();
        self.orgs
            .0
            .entry(org.into())
            .or_default()
            .invites
            .push(invite);
        self.save_orgs()?;
        Ok(link)
    }

    /// Claim an invite link (on the new device). Connect to `Claim::relay` and
    /// announce `Claim::org` (the client has no proof yet, so it is pending), then
    /// send `Claim::frame`. The admin answers with [`Event::ClaimCode`] (show the
    /// code); [`Event::Joined`] follows once it accepts.
    pub fn claim_invite(&mut self, link: &str) -> Result<Claim, ClientError> {
        let invite = Invite::parse(link).map_err(|e| ClientError::InvalidInvite(e.to_string()))?;
        if invite.is_expired(now_ms()) {
            return Err(ClientError::InvalidInvite("expired".into()));
        }
        let key_package = self.groups.key_package(&self.key)?;
        // The KeyPackage's private part must be stored before it leaves.
        self.save_groups()?;
        let org = invite.org.to_hex();
        self.joining.insert(org.clone(), invite.own_device);
        let body = sync::outer_body(&Outer::Claim {
            token: invite.token,
            proof: invite.claim_proof(&key_package),
            key_package: key_package.clone(),
        });
        self.claiming
            .insert(org.clone(), (invite.clone(), key_package));
        Ok(Claim {
            frame: Frame::InviteClaim {
                org: org.clone(),
                token: hex_encode(&invite.token),
                body,
                to: invite.own_device.map(|d| d.to_hex()),
            },
            relay: invite.relay,
            org,
        })
    }

    /// Admit the device of an [`Event::InviteClaimed`]: adds it to the MLS group,
    /// issues its membership certificate and uses up the invite. Send the frames
    /// (in order: the policy change naming the device, the commit to the group, the
    /// Welcome to the device).
    pub fn accept_claim(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        let (kp, token, _) = self
            .claims
            .remove(&(org.to_string(), device.to_string()))
            .ok_or_else(|| {
                ClientError::InvalidInvite("no pending claim from that device".into())
            })?;
        // One invite admits one device, and only until it expires: the claim was
        // checked when it arrived, but the invite may have been used or expired since.
        let invite = self
            .orgs
            .0
            .get(org)
            .and_then(|s| s.invites.iter().find(|i| i.token == token))
            .cloned()
            .ok_or_else(|| ClientError::InvalidInvite("invite already used".into()))?;
        if invite.is_expired(now_ms()) {
            return Err(ClientError::InvalidInvite("invite expired".into()));
        }
        let own = invite.own_device == Some(self.device_id());
        if !own && !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        if own
            && !self
                .chain(org)
                .is_some_and(|c| c.leaf().is_some_and(|l| !l.own))
        {
            return Err(ClientError::Forbidden(
                "a linked device cannot add devices".into(),
            ));
        }
        // The policy learns that the new device is ours (refused, with nothing
        // changed, if the device already has a role or link), or, for an admin's
        // admission, names it as an editor: devices the policy does not name have
        // no role. Refused if a more senior admin revoked the device.
        let d = DeviceId::from_hex(device)?;
        let link = if own {
            Some(self.policy_commit(org, PolicyOp::LinkDevice { device: d })?)
        } else if self
            .policies
            .get(org)
            .is_some_and(|p| p.creator.is_some() && p.role_of(&d).is_none())
        {
            let op = PolicyOp::SetRole {
                device: d,
                role: Role::Editor,
                cert: None,
            };
            Some(self.policy_commit(org, op)?)
        } else {
            None
        };
        if self.groups.key_package_device(&kp)?.to_hex() != device {
            return Err(ClientError::InvalidInvite(
                "KeyPackage of another device".into(),
            ));
        }
        // The policy change goes out first, in the current epoch: members check the
        // commit that adds the device against it.
        let policy_frame = match &link {
            Some(change) => Some(self.broadcast_frame(org, change)?),
            None => None,
        };
        let added = self.groups.add_member(&self.key, org, &kp)?;
        self.save_groups()?;
        // An admin's chain is its root-issued admin certificate, which vouches for
        // the one we issue now: root -> us -> new device.
        let org_id = DeviceId::from_hex(org)?;
        let mut chain = self.chain(org).cloned().map(|c| c.0).unwrap_or_default();
        chain.push(if own {
            MembershipCert::issue_own(&self.key, org_id, added.member, now_ms())
        } else {
            MembershipCert::issue(&self.key, org_id, added.member, false, now_ms())
        });
        // One use is taken; the invite ends with its last one (REQ-INV-005).
        let mut used_up = true;
        if let Some(st) = self.orgs.0.get_mut(org) {
            for i in st.invites.iter_mut().filter(|i| i.token == token) {
                i.uses = i.uses.saturating_sub(1);
                used_up = i.uses == 0;
            }
            st.invites.retain(|i| i.uses > 0);
        }
        // Other devices' claims on a used-up invite can't be admitted any more.
        if used_up {
            self.claims.retain(|_, (_, t, _)| *t != token);
        }
        self.save_orgs()?;
        let mut frames: Vec<Frame> = policy_frame.into_iter().collect();
        frames.push(Frame::Broadcast {
            org: org.into(),
            body: sync::outer_body(&Outer::Commit(added.commit)),
        });
        frames.push(direct(
            org,
            device,
            sync::outer_body(&Outer::Welcome {
                welcome: added.welcome,
                chain: CertChain(chain).to_hex(),
            }),
        ));
        Ok(frames)
    }

    /// Refuse a pending claim (for example: the short codes did not match). The
    /// invite stays valid until it is used or expires.
    pub fn reject_claim(&mut self, org: &str, device: &str) {
        self.claims.remove(&(org.to_string(), device.to_string()));
    }

    /// Make `device` (hex, a member) an admin of `org`: a root-signed certificate
    /// for the relay and an admin role in the policy. Only the device holding the
    /// org root key can. Send the returned frames; the device re-announces itself.
    pub fn grant_admin(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        let cert = self.root_admin_cert(org, DeviceId::from_hex(device)?)?;
        let change = self.set_role(org, device, Role::Admin)?;
        Ok(vec![
            direct(
                org,
                device,
                sync::outer_body(&Outer::Cert(CertChain(vec![cert]).to_hex())),
            ),
            self.broadcast_frame(org, &change)?,
        ])
    }

    pub(crate) fn save_orgs(&mut self) -> Result<(), ClientError> {
        let sealed = sealed::seal(
            &self.storage_key,
            ORGS_KEY,
            &zeroize::Zeroizing::new(self.orgs.to_bytes()),
        );
        Ok(self.store.put_meta(ORGS_KEY, &sealed)?)
    }

    /// True if `chain` (as sent in an `Outer::Cert`) may replace our proof for
    /// `org`: it makes us an admin where we were not, or its certificate is newer
    /// than ours. A replayed older certificate can't take admin rights away.
    pub(crate) fn is_newer_chain(&self, org: &str, chain: &str) -> bool {
        let Some(current) = self.chain(org).and_then(|c| c.leaf()) else {
            return true;
        };
        let Some(new) = CertChain::from_hex(chain)
            .ok()
            .and_then(|c| c.leaf().cloned())
        else {
            return true; // adopt_chain reports why it is invalid
        };
        (new.admin && !current.admin) || new.issued_ms > current.issued_ms
    }

    /// Store `chain` as our proof for `org` if it proves exactly that.
    pub(crate) fn adopt_chain(&mut self, org: &str, chain: &str) -> Result<bool, String> {
        let org_id = DeviceId::from_hex(org).map_err(|e| e.to_string())?;
        let chain = CertChain::from_hex(chain).map_err(|e| e.to_string())?;
        let proven = chain
            .verify(&org_id, &self.device_id())
            .map_err(|e| e.to_string())?;
        self.orgs.0.entry(org.into()).or_default().chain = Some(chain);
        Ok(proven.admin)
    }
}
