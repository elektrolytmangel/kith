//! High-level client SDK.
//!
//! This is the API apps program against, either directly (Rust desktop
//! apps, Tauri, headless always-on clients) or through the generated
//! bindings in `bindings/` (Swift, Kotlin, JavaScript/WASM).
//!
//! Extension points (see `docs/guides/adapting.md`):
//! - [`Store`]: bring your own storage backend.
//! - [`Signer`]: bring your own key storage (keychain, secure enclave).
//! - [`Transport`]: bring your own connection to the relay or peers.
//! - object types and payload formats are application-defined.

pub use kith_core::{
    Change, ChangeId, DeviceId, IdError, ObjectId, ObjectType, Signer, UnsignedChange,
};
pub use kith_crypto::DeviceKey;
#[cfg(feature = "automerge")]
pub use kith_merge::automerge_merger;
mod sync;

pub use kith_merge::{Materialized, MergeError, Merger};
pub use kith_store::{MemoryStore, Store, StoreError};

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
}

/// Connection to the relay (or a direct peer). Implemented per platform:
/// tokio WebSocket on native, browser WebSocket on web.
pub trait Transport {
    /// Send an encoded protocol frame.
    fn send(&mut self, frame: kith_protocol::Frame) -> Result<(), String>;
}

/// The first frame to send after connecting to the relay.
pub fn hello_frame(signer: &dyn Signer) -> kith_protocol::Frame {
    kith_protocol::Frame::Hello {
        version: kith_protocol::PROTOCOL_VERSION,
        device: signer.device_id().to_hex(),
    }
}

/// The answer to the relay's [`kith_protocol::Frame::Challenge`]: a signature
/// proving this device owns its key (REQ-RELAY-004).
pub fn auth_frame(signer: &dyn Signer, nonce: &str) -> kith_protocol::Frame {
    let msg = kith_protocol::auth_message(&signer.device_id().to_hex(), nonce);
    kith_protocol::Frame::Auth {
        signature: hex_encode(&signer.sign(&msg)),
    }
}

/// The frames to send in answer to a relay's `challenge`: the signature that proves
/// device ownership, then the organization announcement. `None` for any other frame.
pub fn handshake_reply(
    signer: &dyn Signer,
    org: &str,
    frame: &kith_protocol::Frame,
) -> Option<Vec<kith_protocol::Frame>> {
    match frame {
        kith_protocol::Frame::Challenge { nonce } => {
            // Pipelined: a failed auth makes the relay send an error and close.
            Some(vec![auth_frame(signer, nonce), announce_frame(org, "")])
        }
        _ => None,
    }
}

/// Frame announcing membership of `org` after authenticating.
/// The relay does not check `proof` yet (REQ-RELAY-004, phase 5).
pub fn announce_frame(org: &str, proof: &str) -> kith_protocol::Frame {
    kith_protocol::Frame::Announce {
        orgs: vec![kith_protocol::Membership {
            org: org.into(),
            proof: proof.into(),
        }],
    }
}

/// Frame that broadcasts a new change to the other online devices of `org`
/// (REQ-SYNC-004).
/// TODO(phase 4, REQ-ENC-001): encrypt the body with the org's MLS group; until
/// then it is **plaintext on the relay**.
pub fn broadcast_frame(org: &str, change: &Change) -> kith_protocol::Frame {
    kith_protocol::Frame::Broadcast {
        org: org.into(),
        body: sync::change_body(change),
    }
}

/// Result of [`Client::handle_frame`].
#[derive(Debug)]
pub struct Handled {
    /// What the frame meant for the app.
    pub event: Event,
    /// Frames to send to the relay in answer (catch-up replies); usually empty.
    pub replies: Vec<kith_protocol::Frame>,
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
    /// A peer's change was refused (undecodable, bad hash or signature). Nothing was stored.
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
    /// A frame this client has nothing to do with.
    Ignored,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A device's view of the organizations it belongs to.
pub struct Client<S: Store, K: Signer = DeviceKey> {
    key: K,
    store: S,
}

impl<S: Store, K: Signer> Client<S, K> {
    /// Create a client from a signer and a store.
    pub fn new(key: K, store: S) -> Self {
        Self { key, store }
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

    /// The request that starts catch-up (REQ-SYNC-001..003): send it to the relay,
    /// which hands it to one online peer. That peer answers with what we lack and
    /// asks for what it lacks. Works from an empty store (join). The relay's
    /// `Receipt` shows whether a peer was online (`delivered` empty: try later).
    pub fn sync_request_frame(&self, org: &str) -> Result<kith_protocol::Frame, ClientError> {
        let ids = self.store.all_ids()?;
        if ids.len() > sync::MAX_HAVE_IDS {
            return Err(ClientError::SyncTooLarge(ids.len()));
        }
        Ok(kith_protocol::Frame::SyncRequest {
            org: org.into(),
            body: sync::have_body(&ids),
        })
    }

    /// Handle a frame from the relay: validate and store peers' changes
    /// (REQ-SYNC-004), serve catch-up requests and absorb offers (REQ-SYNC-001..003).
    /// Send `Handled::replies` to the relay.
    ///
    /// A bad change from a peer is reported as [`Event::Rejected`], not as an error,
    /// so a misbehaving device cannot break the receive loop. Only local storage
    /// failures return `Err`.
    pub fn handle_frame(&mut self, frame: kith_protocol::Frame) -> Result<Handled, ClientError> {
        use kith_protocol::Frame;
        let event = |event| Handled {
            event,
            replies: vec![],
        };
        Ok(match frame {
            Frame::Deliver { org, from, body } => self.handle_deliver(org, from, &body)?,
            Frame::Presence { org, online } => event(Event::Presence { org, online }),
            Frame::Receipt { delivered } => event(Event::Receipt { delivered }),
            Frame::Error { code, message } => event(Event::RelayError { code, message }),
            _ => event(Event::Ignored),
        })
    }

    fn handle_deliver(
        &mut self,
        org: String,
        from: String,
        body: &[u8],
    ) -> Result<Handled, ClientError> {
        use sync::Message;
        let rejected = |reason: String| Handled {
            event: Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            },
            replies: vec![],
        };
        let msg = match sync::parse(body) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        match msg {
            Message::Change(change) => match self.receive(change.clone()) {
                Ok(is_new) => Ok(Handled {
                    event: Event::Received {
                        org,
                        from,
                        change: Box::new(change),
                        is_new,
                    },
                    replies: vec![],
                }),
                Err(ClientError::Rejected(e)) => Ok(rejected(e.to_string())),
                Err(e) => Err(e),
            },
            Message::Have(theirs) => {
                let diff = kith_sync::diff(&self.store.all_ids()?, &theirs);
                let to_send = self.changes_for(&diff.to_send)?;
                let replies = self.offer_frames(&org, &from, &diff.to_request, &to_send);
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
                    self.offer_frames(&org, &from, &[], &wanted)
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
        &self,
        org: &str,
        to: &str,
        want: &[ChangeId],
        changes: &[Change],
    ) -> Vec<kith_protocol::Frame> {
        sync::offer_bodies(want, changes)
            .into_iter()
            .map(|body| kith_protocol::Frame::Direct {
                org: org.into(),
                to: to.into(),
                body,
            })
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
mod tests {
    use super::*;

    fn client() -> Client<MemoryStore> {
        Client::new(DeviceKey::generate(), MemoryStore::new())
    }

    /// req: REQ-DATA-003
    #[test]
    fn edits_build_history() {
        let mut c = client();
        let created = c.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let oid = created.body.object_id;
        let edited = c.edit(oid, b"v2".to_vec()).unwrap();
        assert_eq!(edited.body.parents, vec![created.change_id]);
        assert_eq!(c.history(&oid).unwrap().len(), 2);
    }

    /// req: REQ-DATA-004
    #[test]
    fn concurrent_edits_fork_without_locks() {
        let mut a = client();
        let mut b = client();
        let created = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let oid = created.body.object_id;
        b.receive(created).unwrap();

        let ea = a.edit(oid, b"a".to_vec()).unwrap();
        let eb = b.edit(oid, b"b".to_vec()).unwrap();
        a.receive(eb).unwrap();
        b.receive(ea).unwrap();

        assert_eq!(a.store().heads(&oid).unwrap().len(), 2);
        assert_eq!(b.store().heads(&oid).unwrap().len(), 2);
    }

    fn deliver(from: &DeviceKey, c: &Change) -> kith_protocol::Frame {
        kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: from.device_id().to_hex(),
            body: sync::change_body(c),
        }
    }

    /// req: REQ-SYNC-004
    #[test]
    fn delivered_change_is_validated_and_stored() {
        let (ka, mut b) = (DeviceKey::generate(), client());
        let mut a = Client::new(ka, MemoryStore::new());
        let c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        let frame = broadcast_frame("org", &c);
        let kith_protocol::Frame::Broadcast { body, .. } = frame else {
            panic!("broadcast frame expected")
        };
        let delivered = kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: a.device_id().to_hex(),
            body,
        };
        let ev = b.handle_frame(delivered.clone()).unwrap().event;
        assert!(matches!(ev, Event::Received { is_new: true, .. }));
        assert!(b.store().contains(&c.change_id).unwrap());
        // Delivered again: valid, but not new.
        assert!(matches!(
            b.handle_frame(delivered).unwrap().event,
            Event::Received { is_new: false, .. }
        ));
    }

    /// req: REQ-SYNC-004
    #[test]
    fn bad_delivered_changes_are_rejected_not_fatal() {
        let ka = DeviceKey::generate();
        let mut b = client();
        let mut a = Client::new(ka, MemoryStore::new());
        let mut c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        c.body.payload = b"tampered".to_vec();
        let from = DeviceKey::generate();
        assert!(matches!(
            b.handle_frame(deliver(&from, &c)).unwrap().event,
            Event::Rejected { .. }
        ));
        assert!(!b.store().contains(&c.change_id).unwrap());
        let garbage = kith_protocol::Frame::Deliver {
            org: "org".into(),
            from: "x".into(),
            body: vec![1, 2, 3],
        };
        assert!(matches!(
            b.handle_frame(garbage).unwrap().event,
            Event::Rejected { .. }
        ));
    }

    /// req: REQ-PERM-002
    #[test]
    fn invalid_change_is_not_stored() {
        let mut a = client();
        let mut b = client();
        let mut c = a.create(ObjectType::new("note"), b"v1".to_vec()).unwrap();
        c.body.payload = b"tampered".to_vec();
        assert!(b.receive(c.clone()).is_err());
        assert!(!b.store().contains(&c.change_id).unwrap());
    }

    // ---- catch-up sync (REQ-SYNC-001..003) ----

    use std::collections::{BTreeSet, VecDeque};

    use kith_protocol::Frame;

    /// What the relay does with a frame: hand the body to the other device.
    fn relay(from: &DeviceId, frame: Frame) -> Option<Frame> {
        match frame {
            Frame::SyncRequest { org, body }
            | Frame::Broadcast { org, body }
            | Frame::Direct { org, body, .. } => Some(Frame::Deliver {
                org,
                from: from.to_hex(),
                body,
            }),
            _ => None,
        }
    }

    /// `requester` asks `partner` to sync; frames are relayed until none are left.
    fn run_sync(
        requester: &mut Client<MemoryStore>,
        partner: &mut Client<MemoryStore>,
    ) -> Vec<Event> {
        let mut queue: VecDeque<(bool, Frame)> =
            VecDeque::from([(true, requester.sync_request_frame("org").unwrap())]);
        let mut events = vec![];
        while let Some((to_partner, frame)) = queue.pop_front() {
            let from = if to_partner {
                requester.device_id()
            } else {
                partner.device_id()
            };
            let Some(delivered) = relay(&from, frame) else {
                continue;
            };
            let handled = if to_partner {
                partner.handle_frame(delivered)
            } else {
                requester.handle_frame(delivered)
            }
            .unwrap();
            events.push(handled.event);
            queue.extend(handled.replies.into_iter().map(|f| (!to_partner, f)));
        }
        events
    }

    fn ids(c: &Client<MemoryStore>) -> BTreeSet<ChangeId> {
        c.store().all_ids().unwrap().into_iter().collect()
    }

    /// req: REQ-SYNC-003
    #[test]
    fn empty_device_gets_the_full_history() {
        let mut a = client();
        let n1 = a.create(ObjectType::new("note"), b"1".to_vec()).unwrap();
        a.edit(n1.body.object_id, b"2".to_vec()).unwrap();
        a.create(ObjectType::new("todo"), b"x".to_vec()).unwrap();
        let mut b = client();
        run_sync(&mut b, &mut a);
        assert_eq!(ids(&b), ids(&a));
        assert_eq!(b.history(&n1.body.object_id).unwrap().len(), 2);
        // The received history is usable: edits build on the received heads.
        let next = b.edit(n1.body.object_id, b"3".to_vec()).unwrap();
        assert_eq!(next.body.parents.len(), 1);
    }

    /// req: REQ-SYNC-001
    /// req: REQ-SYNC-002
    #[test]
    fn both_sides_receive_only_what_they_lack() {
        let mut a = client();
        let mut b = client();
        let shared = a
            .create(ObjectType::new("note"), b"shared".to_vec())
            .unwrap();
        b.receive(shared).unwrap();
        a.create(ObjectType::new("note"), b"only a".to_vec())
            .unwrap();
        b.create(ObjectType::new("note"), b"only b".to_vec())
            .unwrap();

        let events = run_sync(&mut b, &mut a);
        assert_eq!(ids(&a), ids(&b));
        assert_eq!(ids(&a).len(), 3);
        // a served: sends its 1, wants b's 1. b stored 1 and was asked for 1; a stored 1.
        assert!(matches!(
            events[0],
            Event::SyncServed {
                sending: 1,
                wanting: 1,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            Event::SyncReceived {
                stored: 1,
                known: 0,
                rejected: 0,
                requested: 1,
                ..
            }
        ));
        assert!(matches!(
            events[2],
            Event::SyncReceived {
                stored: 1,
                requested: 0,
                ..
            }
        ));
        assert_eq!(events.len(), 3, "no further messages once both sides agree");
    }

    /// req: REQ-SYNC-002
    #[test]
    fn nothing_is_transferred_when_already_in_sync() {
        let mut a = client();
        let mut b = client();
        let c = a.create(ObjectType::new("note"), b"v".to_vec()).unwrap();
        b.receive(c).unwrap();
        let events = run_sync(&mut b, &mut a);
        assert!(matches!(
            events[0],
            Event::SyncServed {
                sending: 0,
                wanting: 0,
                ..
            }
        ));
        assert!(matches!(
            events[1],
            Event::SyncReceived {
                stored: 0,
                known: 0,
                requested: 0,
                ..
            }
        ));
        assert_eq!(events.len(), 2);
    }

    /// req: REQ-SYNC-002
    #[test]
    fn large_histories_are_split_into_several_offers() {
        let mut a = client();
        for _ in 0..3 {
            a.create(ObjectType::new("blob"), vec![7; 300 * 1024])
                .unwrap();
        }
        let all = a.store().all_ids().unwrap();
        let changes: Vec<Change> = all
            .iter()
            .map(|id| a.store().get(id).unwrap().unwrap())
            .collect();
        assert!(sync::offer_bodies(&[], &changes).len() >= 2);
        let mut b = client();
        run_sync(&mut b, &mut a);
        assert_eq!(ids(&b), ids(&a));
    }

    /// req: REQ-SYNC-001
    #[test]
    fn forged_changes_in_an_offer_are_rejected_and_the_rest_is_kept() {
        let mut a = client();
        let good = a.create(ObjectType::new("note"), b"good".to_vec()).unwrap();
        let mut forged = a
            .create(ObjectType::new("note"), b"forged".to_vec())
            .unwrap();
        forged.body.payload = b"tampered".to_vec();
        let mut b = client();
        let from = a.device_id();
        let body = sync::offer_bodies(&[], &[good.clone(), forged.clone()]).remove(0);
        let handled = b
            .handle_frame(Frame::Deliver {
                org: "org".into(),
                from: from.to_hex(),
                body,
            })
            .unwrap();
        assert!(matches!(
            handled.event,
            Event::SyncReceived {
                stored: 1,
                rejected: 1,
                ..
            }
        ));
        assert!(b.store().contains(&good.change_id).unwrap());
        assert!(!b.store().contains(&forged.change_id).unwrap());
    }

    /// req: REQ-SYNC-001
    #[test]
    fn malformed_sync_bodies_are_rejected_not_fatal() {
        let mut b = client();
        for body in [vec![], vec![2], vec![3, 0, 0, 0, 9], vec![42, 1, 2, 3]] {
            let h = b
                .handle_frame(Frame::Deliver {
                    org: "org".into(),
                    from: "x".into(),
                    body,
                })
                .unwrap();
            assert!(matches!(h.event, Event::Rejected { .. }));
            assert!(h.replies.is_empty());
        }
    }
}
