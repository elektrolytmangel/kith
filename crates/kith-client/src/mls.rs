//! MLS group membership, removal and revocation notices (REQ-ENC-001..004).

use super::*;

impl<S: Store, K: Signer> Client<S, K> {
    // ---- MLS group (REQ-ENC-001..004) ----

    /// True if this device is a member of `org`'s group (it can send and read).
    pub fn is_member(&self, org: &str) -> bool {
        self.groups.is_member(org)
    }

    /// Current epoch of `org`'s group.
    pub fn group_epoch(&self, org: &str) -> Result<u64, ClientError> {
        Ok(self.groups.epoch(org)?)
    }

    /// Devices (hex) in `org`'s group.
    pub fn group_members(&self, org: &str) -> Result<Vec<String>, ClientError> {
        Ok(self
            .groups
            .members(org)?
            .iter()
            .map(DeviceId::to_hex)
            .collect())
    }

    /// A certified member without MLS state for `org` (restored from a backup) asks
    /// an online peer to re-add it, once.
    pub(crate) fn rejoin_if_needed(
        &mut self,
        org: &str,
        online: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let me = self.device_id().to_hex();
        if self.groups.has_group(org)
            || self.chain(org).is_none()
            || self.rejoin_asked.contains(org)
        {
            return Ok(vec![]);
        }
        let Some(peer) = online.iter().find(|d| **d != me) else {
            return Ok(vec![]);
        };
        self.rejoin_asked.insert(org.into());
        Ok(vec![self.readd_request_frame(org, org, peer)?])
    }

    /// Ask the member `to` to re-add this device (after a fork or falling too far
    /// behind, REQ-ENC-004): sends a fresh KeyPackage.
    pub(crate) fn readd_request_frame(
        &mut self,
        org: &str,
        group: &str,
        to: &str,
    ) -> Result<Frame, ClientError> {
        let peer = DeviceId::from_hex(to)?;
        let key_package = self.groups.key_package(&self.key)?;
        // The private part must be stored before the KeyPackage leaves.
        self.save_groups()?;
        self.welcome_from.insert(group.into(), peer);
        Ok(direct(
            org,
            to,
            sync::outer_body(&Outer::KeyPackage {
                group: group.into(),
                key_package,
            }),
        ))
    }

    pub(crate) fn readded_frames(&self, org: &str, added: kith_crypto::Added) -> Vec<Frame> {
        vec![
            Frame::Broadcast {
                org: org.into(),
                body: sync::outer_body(&Outer::Commit(added.commit)),
            },
            direct(
                org,
                &added.member.to_hex(),
                // A re-added device keeps its certificate.
                sync::outer_body(&Outer::Welcome {
                    welcome: added.welcome,
                    chain: String::new(),
                }),
            ),
        ]
    }

    /// Remove `device` (hex) from `org` (REQ-INV-004): out of the MLS group, so it
    /// cannot read anything sent afterwards, and revoked in the policy, so its
    /// changes this device has not seen are rejected everywhere. Admins only. Send
    /// the returned frames in order.
    pub fn remove_member(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        // The user's other devices (ADR 0011) go with it: revoked by the policy
        // through the link, removed from the group here.
        let primary = DeviceId::from_hex(device)?;
        let members = self.groups.members(org)?;
        let linked: Vec<DeviceId> = self
            .policies
            .get(org)
            .map_or(vec![], |p| p.linked_to(&primary))
            .into_iter()
            .filter(|d| members.contains(d))
            .collect();
        let revocation = self.revoke(org, device)?;
        // The relay hears of it too (REQ-INV-004): a signed notice, repeated on
        // every announce, so it refuses the device and the ones it certified.
        // Signed by the root key when we hold it: only that removes an admin at the
        // relay, and it stays valid whatever happens to our own admin rights.
        let root = self.orgs.0.get(org).and_then(|s| s.root);
        let notice = match root {
            Some(root) => {
                Revocation::issue_by_root(&DeviceKey::from_secret_bytes(&root), primary, now_ms())
            }
            None => Revocation::issue(
                &self.key,
                self.chain(org)
                    .cloned()
                    .ok_or_else(|| ClientError::NotAdmin(org.into()))?,
                DeviceId::from_hex(org)?,
                primary,
                now_ms(),
            ),
        };
        self.revocations.push(notice);
        self.save_revocations()?;
        let mut frames = vec![];
        let mut gone = vec![primary];
        gone.extend(linked);
        for d in gone {
            let commit = self.groups.remove_member(&self.key, org, d)?;
            self.save_groups()?;
            frames.push(Frame::Broadcast {
                org: org.into(),
                body: sync::outer_body(&Outer::Commit(commit)),
            });
        }
        frames.push(self.broadcast_frame(org, &revocation)?);
        // The other admins and the always-on client keep the notice too, so one of
        // them can repeat it if this device is gone (ADR 0024).
        let shared = vec![self.revocations[self.revocations.len() - 1].to_hex()];
        for body in sync::notices_bodies(&shared) {
            let body = self.app_body(org, &body)?;
            self.save_groups()?;
            frames.push(Frame::Broadcast {
                org: org.into(),
                body,
            });
        }
        frames.push(self.announce_frame(org));
        Ok(frames)
    }

    /// Number of revocation notices this device repeats to the relay for `org`.
    pub fn held_revocations(&self, org: &str) -> usize {
        self.revocations
            .iter()
            .filter(|r| r.org.to_hex() == org)
            .count()
    }

    /// Keep notices that other members shared (ADR 0024). Only admins and the
    /// always-on client keep them: they are the ones that repeat notices on announce.
    /// Each must verify for `org` on its own, so a member cannot plant anything.
    pub(crate) fn learn_notices(&mut self, org: &str, lines: &[String]) -> Result<(), ClientError> {
        if !(self.always_on || self.is_admin(org)) || self.chain(org).is_none() {
            return Ok(());
        }
        let Ok(org_id) = DeviceId::from_hex(org) else {
            return Ok(());
        };
        let mut changed = false;
        for line in lines {
            let Ok(notice) = Revocation::from_hex(line) else {
                continue;
            };
            if notice.verify(&org_id).is_err()
                || self.held_revocations(org) >= MAX_HELD_NOTICES
                || self.revocations.iter().any(|r| r == &notice)
            {
                continue;
            }
            self.revocations.push(notice);
            changed = true;
        }
        if changed {
            self.save_revocations()?;
        }
        Ok(())
    }

    pub(crate) fn save_revocations(&mut self) -> Result<(), ClientError> {
        let text: String = self.revocations.iter().map(|r| r.to_hex() + "\n").collect();
        Ok(self.store.put_meta(REVOCATIONS_KEY, text.as_bytes())?)
    }

    /// Rotate this device's key in `org`'s group (MLS update, REQ-ENC-003): call
    /// it periodically, e.g. weekly or on start after a long pause. Send the
    /// returned commit.
    pub fn rotate_key(&mut self, org: &str) -> Result<Frame, ClientError> {
        let commit = self.groups.self_update(&self.key, org)?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body: sync::outer_body(&Outer::Commit(commit)),
        })
    }
}
