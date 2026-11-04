//! High-level client SDK.
//!
//! This is the API apps program against, either directly (Rust desktop
//! apps, Tauri, headless always-on clients) or through the generated
//! bindings in `bindings/` (Swift, Kotlin, JavaScript/WASM).
//!
//! Every relay body is end-to-end encrypted with the organization's MLS group
//! (REQ-ENC-001, ADR 0004): create the group with [`Client::create_group`] on the
//! first device, then admit devices with [`Client::join_request_frame`] (new
//! device) and [`Client::add_member`] (member). Plaintext bodies are refused.
//!
//! Extension points (see `docs/guides/adapting.md`):
//! - [`Store`]: bring your own storage backend.
//! - [`Signer`]: bring your own key storage (keychain, secure enclave).
//! - [`Transport`]: bring your own connection to the relay or peers.
//! - object types and payload formats are application-defined.

pub use kith_core::{
    Change, ChangeId, DeviceId, IdError, ObjectId, ObjectType, Signer, UnsignedChange,
};
pub use kith_crypto::{DeviceKey, GroupError, Groups};
#[cfg(feature = "automerge")]
pub use kith_merge::automerge_merger;
mod sync;

pub use kith_merge::{Materialized, MergeError, Merger};
pub use kith_store::{MemoryStore, Store, StoreError};

use kith_crypto::CommitOutcome;
use kith_protocol::Frame;
use sync::Outer;

/// Key under which the MLS state is kept in the [`Store`] (`Store::put_meta`).
pub const MLS_STATE_KEY: &str = "mls";

/// Library version (all kith crates are versioned together).
pub fn kith_core_version() -> &'static str {
    kith_core::VERSION
}

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Incoming change failed validation.
    #[error("rejected change: {0}")]
    Rejected(#[from] kith_core::ChangeError),
    /// Too many changes for one catch-up request (naive ID exchange).
    #[error("{0} changes are too many for one catch-up request")]
    SyncTooLarge(usize),
    /// Merging an object's history failed.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// Object does not exist locally.
    #[error("unknown object {0}")]
    UnknownObject(ObjectId),
    /// MLS group operation failed (for example: not a member of the org yet).
    #[error(transparent)]
    Group(#[from] GroupError),
    /// Not a valid device ID.
    #[error(transparent)]
    Id(#[from] IdError),
    /// A document's JSON or merge patch is invalid (not JSON, or not an object).
    #[error("invalid document: {0}")]
    InvalidDocument(String),
}

/// Connection to the relay (or a direct peer). Implemented per platform:
/// tokio WebSocket on native, browser WebSocket on web.
pub trait Transport {
    /// Send an encoded protocol frame.
    fn send(&mut self, frame: Frame) -> Result<(), String>;
}

/// The first frame to send after connecting to the relay.
pub fn hello_frame(signer: &dyn Signer) -> Frame {
    Frame::Hello {
        version: kith_protocol::PROTOCOL_VERSION,
        device: signer.device_id().to_hex(),
    }
}

/// The answer to the relay's [`Frame::Challenge`]: a signature proving this
/// device owns its key (REQ-RELAY-004).
pub fn auth_frame(signer: &dyn Signer, nonce: &str) -> Frame {
    let msg = kith_protocol::auth_message(&signer.device_id().to_hex(), nonce);
    Frame::Auth {
        signature: hex_encode(&signer.sign(&msg)),
    }
}

/// The frames to send in answer to a relay's `challenge`: the signature that proves
/// device ownership, then the organization announcement. `None` for any other frame.
pub fn handshake_reply(signer: &dyn Signer, org: &str, frame: &Frame) -> Option<Vec<Frame>> {
    match frame {
        Frame::Challenge { nonce } => {
            // Pipelined: a failed auth makes the relay send an error and close.
            Some(vec![auth_frame(signer, nonce), announce_frame(org, "")])
        }
        _ => None,
    }
}

/// Frame announcing membership of `org` after authenticating.
/// The relay does not check `proof` yet (REQ-RELAY-004, phase 5).
pub fn announce_frame(org: &str, proof: &str) -> Frame {
    Frame::Announce {
        orgs: vec![kith_protocol::Membership {
            org: org.into(),
            proof: proof.into(),
        }],
    }
}

/// Result of [`Client::handle_frame`].
#[derive(Debug)]
pub struct Handled {
    /// What the frame meant for the app.
    pub event: Event,
    /// Frames to send to the relay in answer (catch-up replies); usually empty.
    pub replies: Vec<Frame>,
}

impl Handled {
    fn event(event: Event) -> Self {
        Self {
            event,
            replies: vec![],
        }
    }
}

/// What a frame from the relay meant for this client.
#[derive(Debug)]
pub enum Event {
    /// A peer's change was valid and handled. `is_new` is false if it was already stored.
    Received {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// The change.
        change: Box<Change>,
        /// True if the change was not stored before.
        is_new: bool,
    },
    /// A peer's message was refused (undecodable, not decryptable, bad hash or
    /// signature, unencrypted). Nothing was stored.
    Rejected {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// Why.
        reason: String,
    },
    /// Devices currently online in an org.
    Presence {
        /// Organization.
        org: String,
        /// Online devices (hex).
        online: Vec<String>,
    },
    /// Which devices a broadcast of ours reached.
    Receipt {
        /// Devices that received it.
        delivered: Vec<String>,
    },
    /// The relay refused something.
    RelayError {
        /// Machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// We answered a peer's catch-up request: we sent it what it lacks and asked for
    /// what we lack.
    SyncServed {
        /// The requesting device (hex).
        from: String,
        /// Changes we offered.
        sending: usize,
        /// Changes we asked the peer to send us back.
        wanting: usize,
    },
    /// A peer sent changes for catch-up. Receiving an offer with `requested == 0` and
    /// `rejected == 0` after a [`Client::sync_request_frame`] means we are caught up
    /// with that peer.
    SyncReceived {
        /// The sending device (hex).
        from: String,
        /// Changes that were new and are now stored.
        stored: usize,
        /// Changes that were already known.
        known: usize,
        /// Changes refused (undecodable, bad hash or signature).
        rejected: usize,
        /// Changes the peer asked us to send back (we replied with them).
        requested: usize,
    },
    /// A device asks to join `org`. To admit it, pass `key_package` to
    /// [`Client::add_member`] and send the frames it returns. Ignore it to refuse.
    JoinRequested {
        /// Organization.
        org: String,
        /// The device asking (hex).
        from: String,
        /// Its MLS KeyPackage.
        key_package: Vec<u8>,
    },
    /// This device joined `org`'s group from a Welcome; the reply asks a peer
    /// for the history (catch-up).
    Joined {
        /// Organization.
        org: String,
    },
    /// A commit changed `org`'s group: a member was added or removed, or keys rotated.
    GroupChanged {
        /// Organization.
        org: String,
        /// New epoch.
        epoch: u64,
        /// True if this device was removed: it can no longer read or send in `org`.
        removed: bool,
    },
    /// This device missed commits of `org`'s group; the reply asks `from` for them.
    EpochBehind {
        /// Organization.
        org: String,
        /// The peer whose message showed we are behind (hex).
        from: String,
    },
    /// A peer that was behind got the commits it missed from us (`commits`), or,
    /// if our log does not reach back far enough, a request to be re-added.
    CommitsServed {
        /// Organization.
        org: String,
        /// The peer (hex).
        to: String,
        /// Commits sent.
        commits: usize,
        /// True if we asked the peer to send a KeyPackage instead.
        readd_needed: bool,
    },
    /// We applied commits we had missed (REQ-ENC-002); the reply restarts data
    /// catch-up with that peer.
    CommitsApplied {
        /// Organization.
        org: String,
        /// The sending peer (hex).
        from: String,
        /// Commits applied.
        applied: usize,
        /// Our epoch now.
        epoch: u64,
    },
    /// A peer is too far behind for our log: we asked to be re-added and sent it a
    /// fresh KeyPackage (REQ-ENC-004).
    ReAddRequested {
        /// Organization.
        org: String,
        /// The peer that will re-add us (hex).
        from: String,
    },
    /// We re-added `device`, which had fallen too far behind (REQ-ENC-004).
    MemberReAdded {
        /// Organization.
        org: String,
        /// The device (hex).
        device: String,
    },
    /// Two members committed in the same epoch and the group forked (ADR 0004).
    /// If `we_win` is false this device asked `peer` (on the winning branch) to
    /// re-add it; otherwise it showed `peer` the winning commit so `peer`'s branch
    /// rejoins. Data sent on the losing branch arrives again through catch-up.
    Fork {
        /// Organization.
        org: String,
        /// The peer on the other branch (hex).
        peer: String,
        /// True if our branch won.
        we_win: bool,
    },
    /// A frame this client has nothing to do with.
    Ignored,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn direct(org: &str, to: &str, body: Vec<u8>) -> Frame {
    Frame::Direct {
        org: org.into(),
        to: to.into(),
        body,
    }
}

/// A device's view of the organizations it belongs to.
pub struct Client<S: Store, K: Signer = DeviceKey> {
    key: K,
    store: S,
    groups: Groups,
    /// Per org: the epoch at which we last asked to be re-added after losing a
    /// fork, so one fork sends one request, not one per message.
    readd_asked: std::collections::HashMap<String, u64>,
}

impl<S: Store, K: Signer> Client<S, K> {
    /// Create a client from a signer and a store. Loads the MLS group state from
    /// the store if there is one.
    pub fn new(key: K, store: S) -> Result<Self, ClientError> {
        let groups = match store.get_meta(MLS_STATE_KEY)? {
            Some(bytes) => Groups::from_bytes(&bytes)?,
            None => Groups::new(),
        };
        Ok(Self {
            key,
            store,
            groups,
            readd_asked: Default::default(),
        })
    }

    /// This device's ID.
    pub fn device_id(&self) -> DeviceId {
        self.key.device_id()
    }

    /// Create a new object with an initial payload.
    pub fn create(&mut self, ty: ObjectType, payload: Vec<u8>) -> Result<Change, ClientError> {
        self.commit(ObjectId::random(), ty, vec![], payload)
    }

    /// Append a change to an existing object, building on its current heads.
    /// Never blocks on a lock: concurrent edits become a fork that the merge
    /// layer resolves (REQ-DATA-004).
    pub fn edit(&mut self, object: ObjectId, payload: Vec<u8>) -> Result<Change, ClientError> {
        let hist = self.store.history(&object)?;
        let ty = hist
            .first()
            .map(|c| c.body.object_type.clone())
            .ok_or(ClientError::UnknownObject(object))?;
        let parents = self.store.heads(&object)?;
        self.commit(object, ty, parents, payload)
    }

    /// Validate and store a change received from a peer.
    /// Returns `true` if it was new.
    pub fn receive(&mut self, change: Change) -> Result<bool, ClientError> {
        change.verify()?;
        // TODO(phase 6, REQ-PERM-002): check author permissions under the
        // policy as of the change's parents before storing.
        Ok(self.store.put(change)?)
    }

    // ---- MLS group (REQ-ENC-001..004) ----

    /// Create `org`'s MLS group with this device as the only member. Call it once,
    /// on the device that creates the organization.
    pub fn create_group(&mut self, org: &str) -> Result<(), ClientError> {
        self.groups.create_group(&self.key, org)?;
        self.save_groups()
    }

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

    /// Ask the member `to` (a device ID in hex, e.g. from `Presence`) to add this
    /// device to `org`: sends a fresh KeyPackage. The member sees
    /// [`Event::JoinRequested`]; if it admits us we get [`Event::Joined`].
    pub fn join_request_frame(&mut self, org: &str, to: &str) -> Result<Frame, ClientError> {
        let kp = self.groups.key_package(&self.key)?;
        // The private part must be stored before the KeyPackage leaves.
        self.save_groups()?;
        Ok(direct(org, to, sync::outer_body(&Outer::KeyPackage(kp))))
    }

    /// Add the device whose KeyPackage came with [`Event::JoinRequested`] to
    /// `org`'s group. Send the returned frames: the commit to the group, then the
    /// Welcome to the new device.
    pub fn add_member(&mut self, org: &str, key_package: &[u8]) -> Result<Vec<Frame>, ClientError> {
        let added = self.groups.add_member(&self.key, org, key_package)?;
        self.save_groups()?;
        Ok(self.added_frames(org, added))
    }

    fn added_frames(&self, org: &str, added: kith_crypto::Added) -> Vec<Frame> {
        vec![
            Frame::Broadcast {
                org: org.into(),
                body: sync::outer_body(&Outer::Commit(added.commit)),
            },
            direct(
                org,
                &added.member.to_hex(),
                sync::outer_body(&Outer::Welcome(added.welcome)),
            ),
        ]
    }

    /// Remove `device` (hex) from `org`'s group. Send the returned commit; the
    /// device cannot read anything sent afterwards.
    pub fn remove_member(&mut self, org: &str, device: &str) -> Result<Frame, ClientError> {
        let device = DeviceId::from_hex(device)?;
        let commit = self.groups.remove_member(&self.key, org, device)?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body: sync::outer_body(&Outer::Commit(commit)),
        })
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

    // ---- data sync ----

    /// Frame that broadcasts a new change, encrypted for `org`'s group, to the
    /// other online devices (REQ-SYNC-004).
    pub fn broadcast_frame(&mut self, org: &str, change: &Change) -> Result<Frame, ClientError> {
        let body = self.app_body(org, &sync::change_body(change))?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body,
        })
    }

    /// The request that starts catch-up (REQ-SYNC-001..003): send it to the relay,
    /// which hands it to one online peer. That peer answers with what we lack and
    /// asks for what it lacks. Works from an empty store (join). The relay's
    /// `Receipt` shows whether a peer was online (`delivered` empty: try later).
    pub fn sync_request_frame(&mut self, org: &str) -> Result<Frame, ClientError> {
        let body = self.have_body(org)?;
        self.save_groups()?;
        Ok(Frame::SyncRequest {
            org: org.into(),
            body,
        })
    }

    fn have_body(&mut self, org: &str) -> Result<Vec<u8>, ClientError> {
        let ids = self.store.all_ids()?;
        if ids.len() > sync::MAX_HAVE_IDS {
            return Err(ClientError::SyncTooLarge(ids.len()));
        }
        self.app_body(org, &sync::have_body(&ids))
    }

    /// Encrypt an inner message as an outer `App` body. The caller saves the
    /// MLS state before the body leaves the device.
    fn app_body(&mut self, org: &str, inner: &[u8]) -> Result<Vec<u8>, ClientError> {
        let ct = self.groups.encrypt(&self.key, org, inner)?;
        Ok(sync::outer_body(&Outer::App(ct)))
    }

    fn save_groups(&mut self) -> Result<(), ClientError> {
        Ok(self
            .store
            .put_meta(MLS_STATE_KEY, &self.groups.to_bytes())?)
    }

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
            Frame::Deliver { org, from, body } => self.handle_deliver(org, from, &body)?,
            Frame::Presence { org, online } => Handled::event(Event::Presence { org, online }),
            Frame::Receipt { delivered } => Handled::event(Event::Receipt { delivered }),
            Frame::Error { code, message } => Handled::event(Event::RelayError { code, message }),
            _ => return Ok(Handled::event(Event::Ignored)),
        };
        // Decrypting advances ratchets and replies are encrypted: save before any
        // reply is sent.
        self.save_groups()?;
        Ok(handled)
    }

    fn handle_deliver(
        &mut self,
        org: String,
        from: String,
        body: &[u8],
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
        match outer {
            Outer::App(ct) => self.handle_app(org, from, &ct),
            Outer::Commit(commit) => {
                // A broadcast commit comes from its committer.
                let Ok(committer) = DeviceId::from_hex(&from) else {
                    return Ok(rejected("sender is not a device ID".into()));
                };
                match self.groups.apply_commit(&org, &commit, committer) {
                    Ok(CommitOutcome::Applied { epoch, removed }) => {
                        Ok(Handled::event(Event::GroupChanged {
                            org,
                            epoch,
                            removed,
                        }))
                    }
                    Ok(CommitOutcome::Stale) => Ok(Handled::event(Event::Ignored)),
                    Ok(CommitOutcome::Fork { we_win, .. }) => self.on_fork(org, from, we_win),
                    Err(GroupError::EpochGap { local, .. }) => Ok(self.behind(org, from, local)),
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::Welcome(welcome) => {
                let joined = match self.groups.join(&welcome) {
                    Ok(o) => o,
                    Err(e) => return Ok(rejected(e.to_string())),
                };
                self.readd_asked.remove(&joined);
                // Start from whatever we have (usually nothing): ask a peer for history.
                let body = self.have_body(&joined)?;
                Ok(Handled {
                    event: Event::Joined {
                        org: joined.clone(),
                    },
                    replies: vec![Frame::SyncRequest { org: joined, body }],
                })
            }
            Outer::KeyPackage(kp) => {
                let known = self
                    .groups
                    .members(&org)
                    .is_ok_and(|m| m.iter().any(|d| d.to_hex() == from));
                if !known {
                    return Ok(Handled::event(Event::JoinRequested {
                        org,
                        from,
                        key_package: kp,
                    }));
                }
                // A member that lost the group (REQ-ENC-004). Only for its own key.
                match self.groups.readd_member(&self.key, &org, &kp) {
                    Ok(added) if added.member.to_hex() == from => Ok(Handled {
                        replies: self.added_frames(&org, added),
                        event: Event::MemberReAdded { org, device: from },
                    }),
                    Ok(_) => Err(ClientError::Group(GroupError::Invalid(
                        "re-added device does not match the sender".into(),
                    ))),
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::CommitRequest(epoch) => Ok(self.serve_commits(org, from, epoch)?),
            Outer::Commits(commits) => {
                let mut applied = 0;
                for (committer, c) in &commits {
                    match self.groups.apply_commit(&org, c, *committer) {
                        Ok(CommitOutcome::Applied { .. }) => applied += 1,
                        Ok(CommitOutcome::Stale) => {}
                        // The rest of the batch belongs to the other branch.
                        Ok(CommitOutcome::Fork { we_win, .. }) => {
                            return self.on_fork(org, from, we_win);
                        }
                        Err(e) => return Ok(rejected(e.to_string())),
                    }
                }
                let epoch = self.groups.epoch(&org)?;
                // Data sent while we were behind could not be read: resync with this peer.
                let replies = if applied > 0 && self.groups.is_member(&org) {
                    vec![direct(&org, &from, self.have_body(&org)?)]
                } else {
                    vec![]
                };
                Ok(Handled {
                    event: Event::CommitsApplied {
                        org,
                        from,
                        applied,
                        epoch,
                    },
                    replies,
                })
            }
            Outer::ReaddNeeded => {
                // Only a group we have can be re-joined; ignore strangers' requests.
                if self.groups.epoch(&org).is_err() {
                    return Ok(rejected("not in this group".into()));
                }
                let frame = self.join_request_frame(&org, &from)?;
                Ok(Handled {
                    event: Event::ReAddRequested { org, from },
                    replies: vec![frame],
                })
            }
        }
    }

    /// The group forked between us and `peer` (ADR 0004).
    fn on_fork(&mut self, org: String, peer: String, we_win: bool) -> Result<Handled, ClientError> {
        let mut replies = vec![];
        if we_win {
            // Show the peer the commit we followed: it then sees it lost.
            if let Some(c) = self.groups.last_commit(&org) {
                replies.push(direct(
                    &org,
                    &peer,
                    sync::outer_body(&Outer::Commits(vec![(c.committer, c.commit)])),
                ));
            }
        } else {
            let epoch = self.groups.epoch(&org)?;
            if self.readd_asked.get(&org) != Some(&epoch) {
                self.readd_asked.insert(org.clone(), epoch);
                replies.push(self.join_request_frame(&org, &peer)?);
            }
        }
        Ok(Handled {
            event: Event::Fork { org, peer, we_win },
            replies,
        })
    }

    /// We are behind on `org`: ask `from` for the commits since `local`.
    fn behind(&self, org: String, from: String, local: u64) -> Handled {
        Handled {
            replies: vec![direct(
                &org,
                &from,
                sync::outer_body(&Outer::CommitRequest(local)),
            )],
            event: Event::EpochBehind { org, from },
        }
    }

    /// Send `to` the commits since `epoch`, or ask it to be re-added. Starts one
    /// epoch earlier when the log has it, so the peer can tell whether it followed
    /// the same commit out of its previous epoch (fork detection).
    fn serve_commits(&self, org: String, to: String, epoch: u64) -> Result<Handled, ClientError> {
        let since = match epoch.checked_sub(1) {
            Some(prev) if matches!(self.groups.commits_since(&org, prev), Ok(Some(_))) => prev,
            _ => epoch,
        };
        let (bodies, commits, readd_needed) = match self.groups.commits_since(&org, since) {
            Ok(Some(cs)) => {
                let n = cs.len();
                (sync::commits_bodies(cs), n, false)
            }
            Ok(None) => (vec![sync::outer_body(&Outer::ReaddNeeded)], 0, true),
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
                org,
                to,
                commits,
                readd_needed,
            },
        })
    }

    fn handle_app(&mut self, org: String, from: String, ct: &[u8]) -> Result<Handled, ClientError> {
        // A sender at an older epoch missed commits: send them along (REQ-ENC-002).
        let help = match (Groups::message_epoch(ct), self.groups.epoch(&org)) {
            (Ok(theirs), Ok(ours)) if theirs < ours => {
                self.serve_commits(org.clone(), from.clone(), theirs)?
                    .replies
            }
            _ => vec![],
        };
        let mut handled = match self.groups.decrypt(&org, ct) {
            Ok(d) if d.sender.to_hex() == from => self.handle_plain(org, from, &d.plaintext)?,
            Ok(_) => Handled::event(Event::Rejected {
                org,
                from,
                reason: "MLS sender does not match the relay's sender".into(),
            }),
            Err(GroupError::EpochGap { local, .. }) => self.behind(org, from, local),
            Err(e) => {
                // A member's message for our own epoch that we cannot read means we
                // are on different branches of a fork: ask for its commits, which
                // start one epoch back and show the fork.
                let probe = self.same_epoch_member(&org, &from, ct);
                let mut h = Handled::event(Event::Rejected {
                    org: org.clone(),
                    from: from.clone(),
                    reason: e.to_string(),
                });
                if let Some(local) = probe {
                    h.replies.push(direct(
                        &org,
                        &from,
                        sync::outer_body(&Outer::CommitRequest(local)),
                    ));
                }
                h
            }
        };
        // Commits first, so the peer can read the encrypted replies that follow.
        handled.replies.splice(0..0, help);
        Ok(handled)
    }

    /// Our epoch, if `ct` is for it and `from` is a member of our view of the group.
    fn same_epoch_member(&self, org: &str, from: &str, ct: &[u8]) -> Option<u64> {
        let local = self.groups.epoch(org).ok()?;
        let member = self
            .groups
            .members(org)
            .ok()?
            .iter()
            .any(|d| d.to_hex() == from);
        (member && Groups::message_epoch(ct).ok()? == local).then_some(local)
    }

    fn handle_plain(
        &mut self,
        org: String,
        from: String,
        plaintext: &[u8],
    ) -> Result<Handled, ClientError> {
        use sync::Message;
        let rejected = |reason: String| {
            Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            })
        };
        let msg = match sync::parse(plaintext) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        match msg {
            Message::Change(change) => match self.receive(change.clone()) {
                Ok(is_new) => Ok(Handled::event(Event::Received {
                    org,
                    from,
                    change: Box::new(change),
                    is_new,
                })),
                Err(ClientError::Rejected(e)) => Ok(rejected(e.to_string())),
                Err(e) => Err(e),
            },
            Message::Have(theirs) => {
                let diff = kith_sync::diff(&self.store.all_ids()?, &theirs);
                let to_send = self.changes_for(&diff.to_send)?;
                let replies = self.offer_frames(&org, &from, &diff.to_request, &to_send)?;
                Ok(Handled {
                    event: Event::SyncServed {
                        from,
                        sending: to_send.len(),
                        wanting: diff.to_request.len(),
                    },
                    replies,
                })
            }
            Message::Offer { want, changes } => {
                let (mut stored, mut known, mut rejected_n) = (0, 0, 0);
                for enc in changes {
                    let change = match kith_store::codec::decode_change(&enc) {
                        Ok(c) => c,
                        Err(_) => {
                            rejected_n += 1;
                            continue;
                        }
                    };
                    match self.receive(change) {
                        Ok(true) => stored += 1,
                        Ok(false) => known += 1,
                        Err(ClientError::Rejected(_)) => rejected_n += 1,
                        Err(e) => return Err(e),
                    }
                }
                // Reply only if asked, so two offers never ping-pong forever.
                let replies = if want.is_empty() {
                    vec![]
                } else {
                    let wanted = self.changes_for(&want)?;
                    self.offer_frames(&org, &from, &[], &wanted)?
                };
                Ok(Handled {
                    event: Event::SyncReceived {
                        from,
                        stored,
                        known,
                        rejected: rejected_n,
                        requested: want.len(),
                    },
                    replies,
                })
            }
        }
    }

    /// The stored changes with these IDs (unknown IDs are skipped), oldest first.
    fn changes_for(&self, ids: &[ChangeId]) -> Result<Vec<Change>, ClientError> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.store.get(id)? {
                out.push(c);
            }
        }
        out.sort_by_key(|c| (c.body.timestamp_ms, c.change_id));
        Ok(out)
    }

    fn offer_frames(
        &mut self,
        org: &str,
        to: &str,
        want: &[ChangeId],
        changes: &[Change],
    ) -> Result<Vec<Frame>, ClientError> {
        sync::offer_bodies(want, changes)
            .into_iter()
            .map(|inner| Ok(direct(org, to, self.app_body(org, &inner)?)))
            .collect()
    }

    /// The merged state of an object: all its changes, including concurrent
    /// forks, combined by `merger` (REQ-DATA-004). Does not change the store;
    /// the next `edit` names all current heads as parents, which joins forks.
    pub fn materialize<M: Merger>(
        &self,
        object: &ObjectId,
        merger: &M,
    ) -> Result<Materialized<M::State>, ClientError> {
        let hist = self.store.history(object)?;
        if hist.is_empty() {
            return Err(ClientError::UnknownObject(*object));
        }
        Ok(merger.materialize(&hist)?)
    }

    /// Full change history of an object.
    pub fn history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        Ok(self.store.history(object)?)
    }

    /// The signer this client was created with (for `DeviceKey`: read the
    /// secret seed to persist it, see `DeviceKey::secret_bytes`).
    pub fn signer(&self) -> &K {
        &self.key
    }

    /// Access the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn commit(
        &mut self,
        object_id: ObjectId,
        object_type: ObjectType,
        parents: Vec<ChangeId>,
        payload: Vec<u8>,
    ) -> Result<Change, ClientError> {
        let change = Change::sign(
            UnsignedChange {
                object_id,
                object_type,
                parents,
                timestamp_ms: now_ms(),
                payload,
            },
            &self.key,
        );
        self.store.put(change.clone())?;
        Ok(change)
    }
}

/// JSON documents (REQ-DATA-004): objects whose changes are Automerge changes,
/// read and written as JSON. Concurrent patches of different keys both survive;
/// the same key gets the same winner on every device.
#[cfg(feature = "automerge")]
impl<S: Store, K: Signer> Client<S, K> {
    /// Create a document from a JSON object. Broadcast the returned change like any other.
    pub fn create_document(&mut self, ty: ObjectType, json: &str) -> Result<Change, ClientError> {
        let patch = parse_object(json)?;
        let mut doc = automerge_merger::automerge::AutoCommit::new();
        let payload =
            automerge_merger::author(&mut doc, |d| automerge_merger::merge_patch(d, &patch))?
                // An empty object still needs a change to exist.
                .unwrap_or_default();
        self.create(ty, payload)
    }

    /// Change a document with an RFC 7396 JSON merge patch (`null` removes a key,
    /// objects merge, other values replace). `None` if the patch changes nothing.
    pub fn update_document(
        &mut self,
        object: ObjectId,
        patch: &str,
    ) -> Result<Option<Change>, ClientError> {
        let patch = parse_object(patch)?;
        let mut doc = self
            .materialize(&object, &automerge_merger::AutomergeMerger)?
            .state;
        match automerge_merger::author(&mut doc, |d| automerge_merger::merge_patch(d, &patch))? {
            Some(payload) => Ok(Some(self.edit(object, payload)?)),
            None => Ok(None),
        }
    }

    /// The merged state of a document as JSON, all forks included.
    pub fn document_json(&self, object: &ObjectId) -> Result<String, ClientError> {
        let doc = self
            .materialize(object, &automerge_merger::AutomergeMerger)?
            .state;
        Ok(automerge_merger::to_json(&doc).to_string())
    }
}

#[cfg(feature = "automerge")]
fn parse_object(json: &str) -> Result<serde_json::Value, ClientError> {
    match serde_json::from_str(json) {
        Ok(v @ serde_json::Value::Object(_)) => Ok(v),
        Ok(_) => Err(ClientError::InvalidDocument("must be a JSON object".into())),
        Err(e) => Err(ClientError::InvalidDocument(e.to_string())),
    }
}

/// Wall-clock time in milliseconds since the Unix epoch.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock time in milliseconds since the Unix epoch.
/// `std::time::SystemTime::now()` panics on wasm32-unknown-unknown, so use the JS clock.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(test)]
mod tests;
