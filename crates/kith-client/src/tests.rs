use std::collections::{BTreeSet, VecDeque};

use kith_protocol::Frame;

use super::*;

/// Every test org uses this root key, so its ID is a constant.
const ROOT_SECRET: [u8; 32] = [7; 32];
static ORG: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    DeviceKey::from_secret_bytes(&ROOT_SECRET)
        .device_id()
        .to_hex()
});

type C = Client<MemoryStore>;

fn client() -> C {
    Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap()
}

fn hex(c: &C) -> String {
    c.device_id().to_hex()
}

/// A relay in memory: devices `0..n`, all online in `ORG` unless `offline`.
struct Net {
    devs: Vec<C>,
    offline: BTreeSet<usize>,
    /// Every event, with the device that saw it.
    events: Vec<(usize, Event)>,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            devs: (0..n).map(|_| client()).collect(),
            offline: BTreeSet::new(),
            events: vec![],
        }
    }

    fn idx(&self, hex_id: &str) -> Option<usize> {
        self.devs.iter().position(|d| hex(d) == hex_id)
    }

    /// Route frames sent by `from` until no frame is left. Returns the events of
    /// this run.
    fn send(&mut self, from: usize, frames: Vec<Frame>) -> Vec<(usize, Event)> {
        let mut queue: VecDeque<(usize, Frame)> = frames.into_iter().map(|f| (from, f)).collect();
        let start = self.events.len();
        while let Some((sender, frame)) = queue.pop_front() {
            let from_hex = hex(&self.devs[sender]);
            let online = |i: usize, net: &Net| i != sender && !net.offline.contains(&i);
            let claim = matches!(frame, Frame::InviteClaim { .. });
            let (targets, body): (Vec<usize>, Vec<u8>) = match frame {
                Frame::Broadcast { body, .. } => (
                    (0..self.devs.len()).filter(|&i| online(i, self)).collect(),
                    body,
                ),
                Frame::SyncRequest { body, .. } => (
                    (0..self.devs.len())
                        .filter(|&i| online(i, self))
                        .take(1)
                        .collect(),
                    body,
                ),
                Frame::Direct { to, body, .. } => (
                    self.idx(&to)
                        .filter(|&i| online(i, self))
                        .into_iter()
                        .collect(),
                    body,
                ),
                // The relay sends claims to the named device (own-device invites) or the
                // org's admins; here: that device, or everyone else.
                Frame::InviteClaim { body, to, .. } => (
                    (0..self.devs.len())
                        .filter(|&i| online(i, self))
                        .filter(|&i| to.as_ref().is_none_or(|t| *t == hex(&self.devs[i])))
                        .collect(),
                    body,
                ),
                _ => continue,
            };
            for t in targets {
                let handled = self.devs[t]
                    .handle_frame(if claim {
                        Frame::ClaimDeliver {
                            org: ORG.clone(),
                            from: from_hex.clone(),
                            body: body.clone(),
                        }
                    } else {
                        Frame::Deliver {
                            org: ORG.clone(),
                            from: from_hex.clone(),
                            body: body.clone(),
                        }
                    })
                    .unwrap();
                self.events.push((t, handled.event));
                queue.extend(handled.replies.into_iter().map(|f| (t, f)));
            }
        }
        self.events.drain(start..).collect()
    }

    /// Device 0 creates the org; it invites the others and admits them.
    fn org(n: usize) -> Self {
        let mut net = Self::new(n);
        assert_eq!(
            net.devs[0].create_org_with_root_key(&ROOT_SECRET).unwrap(),
            *ORG
        );
        for i in 1..n {
            net.admit(0, i);
        }
        net
    }

    /// `admin` invites `new`, which claims; `admin` checks the code and accepts.
    fn admit(&mut self, admin: usize, new: usize) {
        let link = self.devs[admin]
            .create_invite(&ORG, "ws://relay/v1/ws", 60_000)
            .unwrap();
        let claim = self.devs[new].claim_invite(&link).unwrap();
        assert_eq!(claim.org, *ORG);
        let events = self.send(new, vec![claim.frame]);
        let code = events
            .into_iter()
            .find_map(|(i, e)| match e {
                Event::InviteClaimed { code, .. } if i == admin => Some(code),
                _ => None,
            })
            .expect("the claim reaches the admin");
        assert_eq!(code, claim.code, "both screens show the same code");
        let new_hex = hex(&self.devs[new]);
        let frames = self.devs[admin].accept_claim(&ORG, &new_hex).unwrap();
        let events = self.send(admin, frames);
        assert!(
            events
                .iter()
                .any(|(i, e)| *i == new && matches!(e, Event::Joined { .. }))
        );
        assert!(self.devs[new].is_member(&ORG));
    }

    fn create(&mut self, who: usize, payload: &[u8]) -> Change {
        let c = self.devs[who]
            .create(ObjectType::new("note"), payload.to_vec())
            .unwrap();
        let f = self.devs[who].broadcast_frame(&ORG, &c).unwrap();
        self.send(who, vec![f]);
        c
    }

    fn ids(&self, who: usize) -> BTreeSet<ChangeId> {
        self.devs[who]
            .store()
            .all_ids()
            .unwrap()
            .into_iter()
            .collect()
    }
}

fn received_by(events: &[(usize, Event)], who: usize) -> usize {
    events
        .iter()
        .filter(|(i, e)| *i == who && matches!(e, Event::Received { is_new: true, .. }))
        .count()
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

// ---- encryption (REQ-ENC-001..004) ----

/// req: REQ-ENC-001
/// req: REQ-SYNC-004
#[test]
fn broadcasts_are_encrypted_and_reach_members() {
    let mut net = Net::org(3);
    let c = net.devs[1]
        .create(ObjectType::new("note"), b"top secret".to_vec())
        .unwrap();
    let frame = net.devs[1].broadcast_frame(&ORG, &c).unwrap();
    let Frame::Broadcast { body, .. } = &frame else {
        panic!("broadcast expected")
    };
    assert!(
        !body.windows(10).any(|w| w == b"top secret"),
        "the relay must not see the payload"
    );
    let events = net.send(1, vec![frame]);
    assert_eq!(received_by(&events, 0), 1);
    assert_eq!(received_by(&events, 2), 1);
    assert!(net.devs[2].store().contains(&c.change_id).unwrap());
}

/// req: REQ-ENC-001
#[test]
fn plaintext_and_outsiders_are_refused() {
    let mut net = Net::org(2);
    let mut outsider = client();
    // Not a member: it cannot create in the org, and its local data stays local.
    assert!(
        outsider
            .create_in(Scope::parse(&ORG).unwrap(), ObjectType::new("note"), vec![])
            .is_err()
    );
    let local = outsider
        .create(ObjectType::new("note"), b"x".to_vec())
        .unwrap();
    assert!(local.body.scope.is_local());
    assert!(outsider.broadcast_frame(&ORG, &local).is_err());
    // A modified client signs a change for the org anyway.
    let c = Change::sign(
        UnsignedChange {
            scope: Scope::parse(&ORG).unwrap(),
            object_id: ObjectId::random(),
            object_type: ObjectType::new("note"),
            parents: vec![],
            timestamp_ms: 1,
            payload: b"x".to_vec(),
        },
        outsider.signer(),
    );
    // No group: it cannot produce a broadcast.
    assert!(matches!(
        outsider.broadcast_frame(&ORG, &c),
        Err(ClientError::Group(_))
    ));
    // The pre-MLS plaintext body is refused.
    let plain = Frame::Deliver {
        org: ORG.clone(),
        from: hex(&outsider),
        body: sync::change_body(&c),
    };
    let h = net.devs[0].handle_frame(plain).unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }));
    assert!(!net.devs[0].store().contains(&c.change_id).unwrap());
    // An outsider with its own group of the same name cannot write into ours.
    outsider.create_group(&ORG).unwrap();
    let frame = outsider.broadcast_frame(&ORG, &c).unwrap();
    let Frame::Broadcast { body, .. } = frame else {
        panic!()
    };
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: hex(&outsider),
            body,
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }));
    assert!(!net.devs[0].store().contains(&c.change_id).unwrap());
}

/// req: REQ-ENC-001
#[test]
fn relay_cannot_attribute_a_message_to_another_device() {
    let mut net = Net::org(3);
    let c = net.devs[1]
        .create(ObjectType::new("note"), b"x".to_vec())
        .unwrap();
    let Frame::Broadcast { body, .. } = net.devs[1].broadcast_frame(&ORG, &c).unwrap() else {
        panic!()
    };
    let spoofed = Frame::Deliver {
        org: ORG.clone(),
        from: hex(&net.devs[2]),
        body,
    };
    let h = net.devs[0].handle_frame(spoofed).unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }));
}

/// req: REQ-ENC-001
#[test]
fn removed_device_gets_nothing_new() {
    let mut net = Net::org(3);
    let removed = hex(&net.devs[2]);
    let frames = net.devs[0].remove_member(&ORG, &removed).unwrap();
    let events = net.send(0, frames);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::GroupChanged { removed: true, .. }))
    );
    assert!(!net.devs[2].is_member(&ORG));
    let events = {
        let c = net.devs[0]
            .create(ObjectType::new("note"), b"after".to_vec())
            .unwrap();
        let f = net.devs[0].broadcast_frame(&ORG, &c).unwrap();
        net.send(0, vec![f])
    };
    assert_eq!(received_by(&events, 1), 1);
    assert_eq!(received_by(&events, 2), 0);
    assert_eq!(net.devs[1].group_members(&ORG).unwrap().len(), 2);
}

/// req: REQ-ENC-002
/// req: REQ-ENC-003
#[test]
fn device_that_missed_commits_catches_up_and_gets_the_data() {
    let mut net = Net::org(3);
    net.offline.insert(2);
    for who in [0, 1] {
        let f = net.devs[who].rotate_key(&ORG).unwrap();
        net.send(who, vec![f]);
    }
    let missed = net.create(1, b"while you were away");
    net.offline.clear();
    assert!(net.devs[2].group_epoch(&ORG).unwrap() < net.devs[0].group_epoch(&ORG).unwrap());

    // The next broadcast is from an epoch device 2 has not reached.
    let events = {
        let c = net.devs[0]
            .create(ObjectType::new("note"), b"now".to_vec())
            .unwrap();
        let f = net.devs[0].broadcast_frame(&ORG, &c).unwrap();
        net.send(0, vec![f])
    };
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::EpochBehind { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::CommitsApplied { applied: 2, .. }))
    );
    assert_eq!(
        net.devs[2].group_epoch(&ORG).unwrap(),
        net.devs[0].group_epoch(&ORG).unwrap()
    );
    // The resync after the commits brought both missed changes.
    assert!(net.devs[2].store().contains(&missed.change_id).unwrap());
    assert_eq!(net.ids(2), net.ids(0));
}

/// req: REQ-ENC-002
#[test]
fn lagging_sender_is_sent_the_commits_it_missed() {
    let mut net = Net::org(2);
    net.offline.insert(1);
    let f = net.devs[0].rotate_key(&ORG).unwrap();
    net.send(0, vec![f]);
    net.offline.clear();
    // Device 1 broadcasts from its old epoch; device 0 still reads it (past epoch
    // keys) and sends device 1 the commit.
    let c = net.devs[1]
        .create(ObjectType::new("note"), b"old epoch".to_vec())
        .unwrap();
    let f = net.devs[1].broadcast_frame(&ORG, &c).unwrap();
    let events = net.send(1, vec![f]);
    assert_eq!(received_by(&events, 0), 1);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::CommitsApplied { applied: 1, .. }))
    );
    assert_eq!(
        net.devs[1].group_epoch(&ORG).unwrap(),
        net.devs[0].group_epoch(&ORG).unwrap()
    );
}

/// req: REQ-ENC-004
#[test]
fn device_beyond_the_commit_log_is_readded_automatically() {
    let mut net = Net::org(3);
    net.offline.insert(2);
    for _ in 0..kith_crypto::group::COMMIT_LOG_LEN + 1 {
        let f = net.devs[0].rotate_key(&ORG).unwrap();
        net.send(0, vec![f]);
    }
    let missed = net.create(0, b"far away");
    net.offline.clear();
    let f = net.devs[2].sync_request_frame(&ORG).unwrap();
    let events = net.send(2, vec![f]);
    assert!(events.iter().any(|(i, e)| *i == 0
        && matches!(
            e,
            Event::CommitsServed {
                readd_needed: true,
                ..
            }
        )));
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::ReAddRequested { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::MemberReAdded { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::Joined { .. }))
    );
    assert!(net.devs[2].store().contains(&missed.change_id).unwrap());
    assert_eq!(net.devs[1].group_members(&ORG).unwrap().len(), 3);
    // And it can talk again.
    let events = {
        let c = net.devs[2]
            .create(ObjectType::new("note"), b"back".to_vec())
            .unwrap();
        let f = net.devs[2].broadcast_frame(&ORG, &c).unwrap();
        net.send(2, vec![f])
    };
    assert_eq!(received_by(&events, 0), 1);
    assert_eq!(received_by(&events, 1), 1);
}

/// req: REQ-ENC-001
#[test]
fn group_state_survives_a_restart() {
    let mut net = Net::org(2);
    net.create(0, b"before");
    // Restart device 1 from its store (the MLS state is in its meta slot).
    let old = std::mem::replace(&mut net.devs[1], client());
    let key = DeviceKey::from_secret_bytes(&old.signer().secret_bytes());
    let Client { store, .. } = old;
    net.devs[1] = Client::new(key, store).unwrap();
    assert!(net.devs[1].is_member(&ORG));
    let events = {
        let c = net.devs[1]
            .create(ObjectType::new("note"), b"after".to_vec())
            .unwrap();
        let f = net.devs[1].broadcast_frame(&ORG, &c).unwrap();
        net.send(1, vec![f])
    };
    assert_eq!(received_by(&events, 0), 1);
    // A corrupt state is an error, not a silent new identity.
    let mut store = MemoryStore::new();
    store.put_meta(MLS_STATE_KEY, b"garbage").unwrap();
    assert!(Client::new(DeviceKey::generate(), store).is_err());
}

// ---- catch-up sync (REQ-SYNC-001..003) ----

/// req: REQ-SYNC-003
#[test]
fn new_member_gets_the_full_history_on_join() {
    let mut net = Net::new(2);
    net.devs[0].create_org_with_root_key(&ROOT_SECRET).unwrap();
    let n1 = net.devs[0]
        .create(ObjectType::new("note"), b"1".to_vec())
        .unwrap();
    net.devs[0].edit(n1.body.object_id, b"2".to_vec()).unwrap();
    net.devs[0]
        .create(ObjectType::new("todo"), b"x".to_vec())
        .unwrap();
    // Joining sends a sync request on its own.
    net.admit(0, 1);
    assert_eq!(net.ids(1), net.ids(0));
    assert_eq!(net.devs[1].history(&n1.body.object_id).unwrap().len(), 2);
    let next = net.devs[1].edit(n1.body.object_id, b"3".to_vec()).unwrap();
    assert_eq!(next.body.parents.len(), 1);
}

/// req: REQ-SYNC-001
/// req: REQ-SYNC-002
#[test]
fn both_sides_receive_only_what_they_lack() {
    let mut net = Net::org(2);
    net.create(0, b"shared");
    net.offline.insert(1);
    net.create(0, b"only 0");
    net.offline = BTreeSet::from([0]);
    net.create(1, b"only 1");
    net.offline.clear();

    let f = net.devs[1].sync_request_frame(&ORG).unwrap();
    let events: Vec<Event> = net.send(1, vec![f]).into_iter().map(|(_, e)| e).collect();
    assert_eq!(net.ids(0), net.ids(1));
    assert_eq!(
        net.ids(0).len(),
        5,
        "3 notes + the policy genesis + member 1 named in the policy"
    );
    // 0 answers the reconciliation; 1 learns it must send 1 and fetch 1.
    assert!(matches!(events[0], Event::SyncServed { .. }));
    assert!(matches!(
        events[1],
        Event::SyncCompared {
            sending: 1,
            wanting: 1,
            ..
        }
    ));
    assert!(matches!(
        events[2],
        Event::SyncReceived {
            stored: 1,
            known: 0,
            rejected: 0,
            requested: 1,
            ..
        }
    ));
    assert!(matches!(
        events[3],
        Event::SyncReceived {
            stored: 1,
            requested: 0,
            ..
        }
    ));
    assert_eq!(events.len(), 4, "no further messages once both sides agree");
}

/// req: REQ-SYNC-002
#[test]
fn nothing_is_transferred_when_already_in_sync() {
    let mut net = Net::org(2);
    net.create(0, b"v");
    let f = net.devs[1].sync_request_frame(&ORG).unwrap();
    let events: Vec<Event> = net.send(1, vec![f]).into_iter().map(|(_, e)| e).collect();
    assert!(matches!(events[0], Event::SyncServed { .. }));
    assert!(matches!(
        events[1],
        Event::SyncCompared {
            sending: 0,
            wanting: 0,
            ..
        }
    ));
    assert_eq!(events.len(), 2, "nothing to send, so no offers");
}

/// req: REQ-SYNC-002
#[test]
fn large_histories_are_split_into_several_offers() {
    let mut net = Net::org(2);
    net.offline.insert(1);
    for _ in 0..3 {
        let c = net.devs[0]
            .create(ObjectType::new("blob"), vec![7; 300 * 1024])
            .unwrap();
        let _ = c;
    }
    net.offline.clear();
    let all = net.devs[0].store().all_ids().unwrap();
    let changes: Vec<Change> = all
        .iter()
        .map(|id| net.devs[0].store().get(id).unwrap().unwrap())
        .collect();
    assert!(sync::offer_bodies(&[], &changes).len() >= 2);
    let f = net.devs[1].sync_request_frame(&ORG).unwrap();
    net.send(1, vec![f]);
    assert_eq!(net.ids(1), net.ids(0));
}

/// Deliver an inner message from `from` to `to`, encrypted like a real peer would.
fn deliver_inner(net: &mut Net, from: usize, to: usize, inner: &[u8]) -> Handled {
    let body = net.devs[from].app_body(&ORG, inner).unwrap();
    let from_hex = hex(&net.devs[from]);
    net.devs[to]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: from_hex,
            body,
        })
        .unwrap()
}

/// req: REQ-SYNC-001
/// req: REQ-SYNC-004
#[test]
fn forged_changes_are_rejected_and_the_rest_is_kept() {
    let mut net = Net::org(2);
    let good = net.devs[0]
        .create(ObjectType::new("note"), b"good".to_vec())
        .unwrap();
    let mut forged = net.devs[0]
        .create(ObjectType::new("note"), b"forged".to_vec())
        .unwrap();
    forged.body.payload = b"tampered".to_vec();
    let inner = sync::offer_bodies(&[], &[good.clone(), forged.clone()]).remove(0);
    let h = deliver_inner(&mut net, 0, 1, &inner);
    assert!(matches!(
        h.event,
        Event::SyncReceived {
            stored: 1,
            rejected: 1,
            ..
        }
    ));
    assert!(net.devs[1].store().contains(&good.change_id).unwrap());
    assert!(!net.devs[1].store().contains(&forged.change_id).unwrap());
    // A forged single change is rejected too, even though it was encrypted by a member.
    let h = deliver_inner(&mut net, 0, 1, &sync::change_body(&forged));
    assert!(matches!(h.event, Event::Rejected { .. }));
}

/// req: REQ-SYNC-001
#[test]
fn malformed_bodies_are_rejected_not_fatal() {
    let mut net = Net::org(2);
    for inner in [vec![], vec![2], vec![3, 0, 0, 0, 9], vec![42, 1, 2, 3]] {
        let h = deliver_inner(&mut net, 0, 1, &inner);
        assert!(matches!(h.event, Event::Rejected { .. }));
        assert!(h.replies.is_empty());
    }
    for body in [
        vec![],
        vec![0x10],
        vec![0x11, 1, 2],
        vec![0x12, 9],
        vec![0x15, 0, 0, 0, 9],
    ] {
        let h = net.devs[1]
            .handle_frame(Frame::Deliver {
                org: ORG.clone(),
                from: "x".into(),
                body,
            })
            .unwrap();
        assert!(matches!(h.event, Event::Rejected { .. }));
        assert!(h.replies.is_empty());
    }
}

// ---- forks: concurrent commits in one epoch (ADR 0004) ----

/// Devices 0 and 1 ordered by device ID: (lower, higher). The lower one's commit
/// wins a fork.
fn by_id(net: &Net) -> (usize, usize) {
    if net.devs[0].device_id().0 < net.devs[1].device_id().0 {
        (0, 1)
    } else {
        (1, 0)
    }
}

/// Every device in `who` is at the same epoch, sees all of `who` as members, and
/// reaches all the others with a broadcast.
fn assert_converged(net: &mut Net, who: &[usize]) {
    let epoch = net.devs[who[0]].group_epoch(&ORG).unwrap();
    for &i in who {
        assert_eq!(net.devs[i].group_epoch(&ORG).unwrap(), epoch, "device {i}");
        assert_eq!(net.devs[i].group_members(&ORG).unwrap().len(), who.len());
    }
    for &i in who {
        let c = net.devs[i]
            .create(ObjectType::new("note"), format!("from {i}").into_bytes())
            .unwrap();
        let f = net.devs[i].broadcast_frame(&ORG, &c).unwrap();
        let events = net.send(i, vec![f]);
        for &j in who.iter().filter(|&&j| j != i) {
            assert_eq!(received_by(&events, j), 1, "{i} -> {j}");
        }
    }
}

fn concurrent_rotations(winner_sends_first: bool) {
    let mut net = Net::org(3);
    let (lo, hi) = by_id(&net);
    let f_lo = net.devs[lo].rotate_key(&ORG).unwrap();
    let f_hi = net.devs[hi].rotate_key(&ORG).unwrap();
    let (first, second) = if winner_sends_first {
        ((lo, f_lo), (hi, f_hi))
    } else {
        ((hi, f_hi), (lo, f_lo))
    };
    let mut events = net.send(first.0, vec![first.1]);
    events.extend(net.send(second.0, vec![second.1]));
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == hi && matches!(e, Event::Fork { we_win: false, .. }))
    );
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == lo && matches!(e, Event::MemberReAdded { .. }))
    );
    assert_converged(&mut net, &[0, 1, 2]);
}

/// req: REQ-ENC-001
#[test]
fn concurrent_commits_converge_when_the_winner_is_heard_first() {
    concurrent_rotations(true);
}

/// req: REQ-ENC-001
#[test]
fn concurrent_commits_converge_when_the_loser_is_heard_first() {
    concurrent_rotations(false);
}

/// req: REQ-ENC-001
/// req: REQ-ENC-002
#[test]
fn a_device_that_missed_the_winning_commit_finds_the_fork_later() {
    let mut net = Net::org(3);
    let (lo, hi) = by_id(&net);
    let f_lo = net.devs[lo].rotate_key(&ORG).unwrap();
    let f_hi = net.devs[hi].rotate_key(&ORG).unwrap();
    // Device 2 follows the losing commit and is offline for the winning one.
    net.send(hi, vec![f_hi]);
    net.offline.insert(2);
    net.send(lo, vec![f_lo]);
    net.offline.clear();
    // The next message from the winning branch shows device 2 that it is behind;
    // the commits it fetches start one epoch back and reveal the fork.
    let c = net.devs[lo]
        .create(ObjectType::new("note"), b"after the fork".to_vec())
        .unwrap();
    let f = net.devs[lo].broadcast_frame(&ORG, &c).unwrap();
    let events = net.send(lo, vec![f]);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::Fork { we_win: false, .. }))
    );
    assert!(net.devs[2].store().contains(&c.change_id).unwrap());
    assert_converged(&mut net, &[0, 1, 2]);
}

// ---- JSON documents (REQ-DATA-004) ----

#[cfg(feature = "automerge")]
mod documents {
    use super::*;

    fn json(c: &C, oid: &ObjectId) -> serde_json::Value {
        serde_json::from_str(&c.document_json(oid).unwrap()).unwrap()
    }

    /// req: REQ-DATA-004
    #[test]
    fn concurrent_patches_merge_on_every_device() {
        let mut net = Net::org(2);
        let created = net.devs[0]
            .create_document(ObjectType::new("acme.todo"), r#"{"title":"draft","n":1}"#)
            .unwrap();
        let oid = created.body.object_id;
        let f = net.devs[0].broadcast_frame(&ORG, &created).unwrap();
        net.send(0, vec![f]);
        // Both edit while apart, then sync.
        net.offline.insert(1);
        let a = net.devs[0]
            .update_document(oid, r#"{"owner":"ann","n":2}"#)
            .unwrap()
            .unwrap();
        let f = net.devs[0].broadcast_frame(&ORG, &a).unwrap();
        net.send(0, vec![f]);
        net.offline.clear();
        net.devs[1]
            .update_document(oid, r#"{"done":true,"title":null}"#)
            .unwrap()
            .unwrap();
        let f = net.devs[1].sync_request_frame(&ORG).unwrap();
        net.send(1, vec![f]);

        let want = serde_json::json!({"owner": "ann", "n": 2, "done": true});
        assert_eq!(json(&net.devs[0], &oid), want);
        assert_eq!(json(&net.devs[1], &oid), want);
        // A patch that changes nothing makes no change.
        assert!(
            net.devs[0]
                .update_document(oid, r#"{"done":true}"#)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bad_documents_are_refused() {
        let mut c = client();
        for bad in ["not json", "[1,2]", "3"] {
            assert!(matches!(
                c.create_document(ObjectType::new("d"), bad),
                Err(ClientError::InvalidDocument(_))
            ));
        }
        let empty = c.create_document(ObjectType::new("d"), "{}").unwrap();
        assert_eq!(c.document_json(&empty.body.object_id).unwrap(), "{}");
        assert!(matches!(
            c.document_json(&ObjectId::random()),
            Err(ClientError::UnknownObject(_))
        ));
    }
}

// ---- invitations (phase 5, ADR 0005) ----

fn claimed_by(events: &[(usize, Event)], who: usize) -> Option<String> {
    events.iter().find_map(|(i, e)| match e {
        Event::InviteClaimed { code, .. } if *i == who => Some(code.clone()),
        _ => None,
    })
}

/// req: REQ-INV-001
/// req: REQ-INV-002
/// req: REQ-ID-003
#[test]
fn invited_devices_get_a_certificate_the_relay_accepts() {
    let net = Net::org(3);
    let org = DeviceId::from_hex(&ORG).unwrap();
    // The creator is the first admin, certified by the root key.
    assert!(net.devs[0].is_admin(&ORG));
    for (i, d) in net.devs.iter().enumerate() {
        let chain = CertChain::from_hex(&d.membership_proof(&ORG)).unwrap();
        let proven = chain.verify(&org, &d.device_id()).unwrap();
        assert_eq!(proven.admin, i == 0);
        assert!(
            matches!(d.announce_frame(&ORG), Frame::Announce { orgs } if !orgs[0].proof.is_empty())
        );
    }
    assert_eq!(net.devs[2].group_members(&ORG).unwrap().len(), 3);
}

/// req: REQ-INV-001
/// req: REQ-INV-002
#[test]
fn invites_are_single_use_expiring_and_need_the_secret() {
    let mut net = Net::org(2);
    net.devs.push(client());
    net.devs.push(client());
    // Only admins invite.
    assert!(matches!(
        net.devs[1].create_invite(&ORG, "ws://r", 60_000),
        Err(ClientError::NotAdmin(_))
    ));
    // Expired links are refused on the claiming side.
    let stale = net.devs[0].create_invite(&ORG, "ws://r", 0).unwrap();
    assert!(matches!(
        net.devs[2].claim_invite(&stale),
        Err(ClientError::InvalidInvite(_))
    ));
    assert!(net.devs[2].claim_invite("https://not-an-invite").is_err());
    // A claim with a guessed secret is rejected.
    let link = net.devs[0].create_invite(&ORG, "ws://r", 60_000).unwrap();
    let mut forged = Invite::parse(&link).unwrap();
    forged.secret = [0; 32];
    let claim = net.devs[2].claim_invite(&forged.to_link()).unwrap();
    let events = net.send(2, vec![claim.frame]);
    assert!(claimed_by(&events, 0).is_none());
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::Rejected { .. }))
    );
    // The real one works once.
    let claim = net.devs[2].claim_invite(&link).unwrap();
    let events = net.send(2, vec![claim.frame]);
    assert_eq!(claimed_by(&events, 0), Some(claim.code));
    let d2 = hex(&net.devs[2]);
    let frames = net.devs[0].accept_claim(&ORG, &d2).unwrap();
    net.send(0, frames);
    assert!(net.devs[2].is_member(&ORG));
    let again = net.devs[3].claim_invite(&link).unwrap();
    let events = net.send(3, vec![again.frame]);
    assert!(claimed_by(&events, 0).is_none(), "the invite is used up");
    // No claim pending: nothing to accept.
    let d3 = hex(&net.devs[3]);
    assert!(net.devs[0].accept_claim(&ORG, &d3).is_err());
}

/// req: REQ-INV-003
#[test]
fn a_rejected_claim_admits_nobody_and_the_invite_stays_valid() {
    let mut net = Net::org(1);
    net.devs.push(client());
    let link = net.devs[0].create_invite(&ORG, "ws://r", 60_000).unwrap();
    let claim = net.devs[1].claim_invite(&link).unwrap();
    let events = net.send(1, vec![claim.frame]);
    assert_eq!(claimed_by(&events, 0), Some(claim.code));
    let d1 = hex(&net.devs[1]);
    net.devs[0].reject_claim(&ORG, &d1);
    assert!(net.devs[0].accept_claim(&ORG, &d1).is_err());
    assert!(!net.devs[1].is_member(&ORG));
    // Claim again (e.g. after comparing codes properly) and get in.
    let claim = net.devs[1].claim_invite(&link).unwrap();
    net.send(1, vec![claim.frame]);
    let frames = net.devs[0].accept_claim(&ORG, &d1).unwrap();
    net.send(0, frames);
    assert!(net.devs[1].is_member(&ORG));
}

/// req: REQ-INV-002
#[test]
fn the_root_makes_admins_who_can_admit_others() {
    let mut net = Net::org(2);
    let d1 = hex(&net.devs[1]);
    let frames = net.devs[0].grant_admin(&ORG, &d1).unwrap();
    let events = net.send(0, frames);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::CertificateUpdated { admin: true, .. }))
    );
    assert!(net.devs[1].is_admin(&ORG));
    // Only the root holder grants admin rights.
    let d0 = hex(&net.devs[0]);
    assert!(matches!(
        net.devs[1].grant_admin(&ORG, &d0),
        Err(ClientError::NotAdmin(_))
    ));
    // The new admin admits a third device: its chain is root -> admin -> device.
    net.devs.push(client());
    net.admit(1, 2);
    let chain = CertChain::from_hex(&net.devs[2].membership_proof(&ORG)).unwrap();
    assert_eq!(chain.0.len(), 2);
    assert!(
        chain
            .verify(&DeviceId::from_hex(&ORG).unwrap(), &net.devs[2].device_id())
            .is_ok()
    );
    assert_converged(&mut net, &[0, 1, 2]);
}

/// req: REQ-INV-002
#[test]
fn strangers_cannot_join_without_an_invite() {
    let mut net = Net::org(1);
    net.devs.push(client());
    let to = hex(&net.devs[0]);
    let f = net.devs[1].readd_request_frame(&ORG, &ORG, &to).unwrap();
    let events = net.send(1, vec![f]);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::Rejected { .. }))
    );
    assert_eq!(net.devs[0].group_members(&ORG).unwrap().len(), 1);
}

/// req: REQ-ID-003
#[test]
fn org_state_survives_a_restart() {
    let mut net = Net::org(1);
    let link = net.devs[0].create_invite(&ORG, "ws://r", 60_000).unwrap();
    let old = std::mem::replace(&mut net.devs[0], client());
    let key = DeviceKey::from_secret_bytes(&old.signer().secret_bytes());
    let Client { store, .. } = old;
    net.devs[0] = Client::new(key, store).unwrap();
    assert!(net.devs[0].is_admin(&ORG));
    // The invite issued before the restart still works.
    net.devs.push(client());
    let claim = net.devs[1].claim_invite(&link).unwrap();
    let events = net.send(1, vec![claim.frame]);
    assert!(claimed_by(&events, 0).is_some());
}

// ---- permissions (phase 6, ADR 0006) ----

/// Broadcast `change` from `who`.
fn spread(net: &mut Net, who: usize, change: &Change) -> Vec<(usize, Event)> {
    let f = net.devs[who].broadcast_frame(&ORG, change).unwrap();
    net.send(who, vec![f])
}

/// A change signed by `who`'s key but made outside its client (a modified app).
fn forged(net: &Net, who: usize, ty: &str, parents: Vec<ChangeId>, object: ObjectId) -> Change {
    Change::sign(
        UnsignedChange {
            scope: Scope::parse(&ORG).unwrap(),
            object_id: object,
            object_type: ObjectType::new(ty),
            parents,
            timestamp_ms: 1,
            payload: b"forged".to_vec(),
        },
        net.devs[who].signer(),
    )
}

/// req: REQ-PERM-001
/// req: REQ-PERM-002
#[test]
fn viewers_cannot_write_and_peers_reject_what_they_send_anyway() {
    let mut net = Net::org(3);
    let d2 = hex(&net.devs[2]);
    let demote = net.devs[0].set_role(&ORG, &d2, Role::Viewer).unwrap();
    spread(&mut net, 0, &demote);
    for i in 0..3 {
        assert_eq!(
            net.devs[i].role_of(&ORG, &d2).unwrap(),
            Some(Role::Viewer),
            "device {i}"
        );
    }
    assert!(matches!(
        net.devs[2].create(ObjectType::new("note"), b"x".to_vec()),
        Err(ClientError::Forbidden(_))
    ));
    // A modified client sends it anyway: honest peers reject it; it never shows up.
    let c = forged(&net, 2, "note", vec![], ObjectId::random());
    let events = spread(&mut net, 2, &c);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::Rejected { .. }))
    );
    for i in 0..2 {
        assert!(net.devs[i].history(&c.body.object_id).unwrap().is_empty());
        assert!(net.devs[i].edit(c.body.object_id, b"y".to_vec()).is_err());
    }
    // Promoted later, the same change counts everywhere (a late grant).
    let promote = net.devs[0].set_role(&ORG, &d2, Role::Editor).unwrap();
    spread(&mut net, 0, &promote);
    assert_eq!(net.devs[1].history(&c.body.object_id).unwrap().len(), 1);
}

/// req: REQ-PERM-001
#[test]
fn write_rules_per_type_and_only_admins_change_the_policy() {
    let mut net = Net::org(2);
    let rule = net.devs[0]
        .set_write_rule(&ORG, "config", Role::Admin)
        .unwrap();
    spread(&mut net, 0, &rule);
    assert!(matches!(
        net.devs[1].create(ObjectType::new("config"), b"x".to_vec()),
        Err(ClientError::Forbidden(_))
    ));
    assert!(
        net.devs[1]
            .create(ObjectType::new("note"), b"ok".to_vec())
            .is_ok()
    );
    let cfg = net.devs[0]
        .create(ObjectType::new("config"), b"theme=dark".to_vec())
        .unwrap();
    let events = spread(&mut net, 0, &cfg);
    assert_eq!(received_by(&events, 1), 1);
    // Members cannot change the policy, and cannot write the policy object directly.
    assert!(matches!(
        net.devs[1].set_write_rule(&ORG, "config", Role::Editor),
        Err(ClientError::NotAdmin(_))
    ));
    let d0 = hex(&net.devs[0]);
    assert!(net.devs[1].set_role(&ORG, &d0, Role::Viewer).is_err());
    assert!(
        net.devs[1]
            .create(ObjectType::new(POLICY_TYPE), vec![])
            .is_err()
    );
}

/// req: REQ-INV-004
#[test]
fn removing_a_member_gives_the_relay_a_signed_notice_that_survives_restarts() {
    let mut net = Net::org(3);
    let d2 = hex(&net.devs[2]);
    let frames = net.devs[0].remove_member(&ORG, &d2).unwrap();
    let Some(Frame::Announce { orgs }) = frames.last() else {
        panic!("remove_member ends with an announce carrying the notice");
    };
    assert_eq!(orgs[0].revoked.len(), 1);
    let org_key = DeviceId::from_hex(&ORG).unwrap();
    let rev = kith_core::membership::Revocation::from_hex(&orgs[0].revoked[0]).unwrap();
    assert_eq!(rev.verify(&org_key), Ok(()));
    assert_eq!(rev.device.to_hex(), d2);
    // Later announces repeat it; devices that did not remove anyone send none.
    assert_eq!(announced(&net.devs[0].announce_frame(&ORG)), 1);
    assert_eq!(announced(&net.devs[1].announce_frame(&ORG)), 0);
}

fn announced(f: &Frame) -> usize {
    match f {
        Frame::Announce { orgs } => orgs[0].revoked.len(),
        _ => panic!("not an announce"),
    }
}

/// req: REQ-PERM-004
/// req: REQ-INV-004
#[test]
fn revocation_keeps_seen_changes_and_rejects_the_rest_with_their_dependents() {
    let mut net = Net::org(3);
    let shared = net.devs[2]
        .create(ObjectType::new("note"), b"seen by all".to_vec())
        .unwrap();
    spread(&mut net, 2, &shared);
    // The admin goes offline; 2 writes, 1 builds on it.
    net.offline.insert(0);
    let unseen = net.devs[2]
        .edit(shared.body.object_id, b"not seen by the admin".to_vec())
        .unwrap();
    spread(&mut net, 2, &unseen);
    let child = net.devs[1]
        .edit(shared.body.object_id, b"builds on it".to_vec())
        .unwrap();
    assert_eq!(child.body.parents, vec![unseen.change_id]);
    spread(&mut net, 1, &child);
    net.offline.clear();
    // The admin removes 2 without having seen those changes.
    let d2 = hex(&net.devs[2]);
    net.offline.insert(1);
    let frames = net.devs[0].remove_member(&ORG, &d2).unwrap();
    net.send(0, frames);
    net.offline.clear();
    // 1 learns about the revocation through catch-up with 0.
    let f = net.devs[1].sync_request_frame(&ORG).unwrap();
    net.send(1, vec![f]);
    assert_eq!(net.devs[1].role_of(&ORG, &d2).unwrap(), None);
    let oid = shared.body.object_id;
    let visible: Vec<ChangeId> = net.devs[1]
        .history(&oid)
        .unwrap()
        .iter()
        .map(|c| c.change_id)
        .collect();
    assert_eq!(
        visible,
        vec![shared.change_id],
        "seen change kept; unseen + dependent hidden"
    );
    // The admin never accepts them either, even if offered again.
    assert!(matches!(
        net.devs[0].receive(unseen.clone()),
        Err(ClientError::Forbidden(_))
    ));
    assert!(matches!(
        net.devs[0].receive(child.clone()),
        Err(ClientError::Forbidden(_))
    ));
    // New edits build on the valid head only.
    let next = net.devs[1].edit(oid, b"again".to_vec()).unwrap();
    assert_eq!(next.body.parents, vec![shared.change_id]);
}

/// req: REQ-PERM-002
#[test]
fn the_policy_reaches_new_members_and_survives_restarts() {
    let mut net = Net::org(1);
    let rule = net.devs[0]
        .set_write_rule(&ORG, "config", Role::Admin)
        .unwrap();
    let _ = rule;
    net.devs.push(client());
    net.admit(0, 1);
    // The new member got the policy with the history and enforces it.
    assert_eq!(
        net.devs[1].policy(&ORG).map(|p| p.write_rule("config")),
        Some(Role::Admin)
    );
    assert!(
        net.devs[1]
            .create(ObjectType::new("config"), vec![1])
            .is_err()
    );
    // And after a restart.
    let old = std::mem::replace(&mut net.devs[1], client());
    let key = DeviceKey::from_secret_bytes(&old.signer().secret_bytes());
    let Client { store, .. } = old;
    net.devs[1] = Client::new(key, store).unwrap();
    assert!(
        net.devs[1]
            .create(ObjectType::new("config"), vec![1])
            .is_err()
    );
    assert!(net.devs[1].create(ObjectType::new("note"), vec![1]).is_ok());
}

// ---- scopes (phase 6b-1) ----

/// req: REQ-PERM-003
#[test]
fn one_store_holds_two_orgs_without_mixing_them() {
    let mut x = client();
    let a = x.create_org().unwrap();
    let b = x.create_org_with_root_key(&[9; 32]).unwrap();
    // With two orgs the scope must be explicit.
    assert!(matches!(
        x.create(ObjectType::new("note"), vec![]),
        Err(ClientError::AmbiguousScope)
    ));
    let in_a = x
        .create_in(
            Scope::parse(&a).unwrap(),
            ObjectType::new("note"),
            b"a".to_vec(),
        )
        .unwrap();
    let in_b = x
        .create_in(
            Scope::parse(&b).unwrap(),
            ObjectType::new("note"),
            b"b".to_vec(),
        )
        .unwrap();
    // Catch-up for org A only ever sees A's changes.
    let a_ids = x.store().scope_ids(&Scope::parse(&a).unwrap()).unwrap();
    assert!(a_ids.contains(&in_a.change_id) && !a_ids.contains(&in_b.change_id));
    // A change of org B cannot be broadcast to org A.
    assert!(x.broadcast_frame(&a, &in_b).is_err());
    // A device that is only in org A refuses B's changes.
    let mut net = Net::org(2);
    let foreign = in_b.clone();
    assert!(matches!(
        net.devs[1].receive(foreign),
        Err(ClientError::Forbidden(_))
    ));
    // Even inside a valid frame of its own org.
    let body = net.devs[0]
        .app_body(&ORG, &sync::change_body(&in_b))
        .unwrap();
    let from = hex(&net.devs[0]);
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }));
    assert!(!net.devs[1].store().contains(&in_b.change_id).unwrap());
}

/// req: REQ-DATA-004
#[test]
fn parents_from_another_object_are_refused() {
    let mut net = Net::org(2);
    let a = net.devs[0]
        .create(ObjectType::new("note"), b"a".to_vec())
        .unwrap();
    net.devs[1].receive(a.clone()).unwrap();
    // A change in another object that names a's change as its parent.
    let c = Change::sign(
        UnsignedChange {
            scope: a.body.scope.clone(),
            object_id: ObjectId::random(),
            object_type: ObjectType::new("note"),
            parents: vec![a.change_id],
            timestamp_ms: 1,
            payload: b"b".to_vec(),
        },
        net.devs[0].signer(),
    );
    assert!(matches!(
        net.devs[1].receive(c.clone()),
        Err(ClientError::Forbidden(_))
    ));
    assert!(!net.devs[1].store().contains(&c.change_id).unwrap());
}

#[test]
fn local_data_stays_local_and_edits_keep_their_scope() {
    let mut net = Net::new(1);
    let note = net.devs[0]
        .create(ObjectType::new("note"), b"before joining".to_vec())
        .unwrap();
    assert!(note.body.scope.is_local());
    net.devs[0].create_org_with_root_key(&ROOT_SECRET).unwrap();
    // The old object stays local; new ones go to the org.
    let edit = net.devs[0]
        .edit(note.body.object_id, b"still local".to_vec())
        .unwrap();
    assert!(edit.body.scope.is_local());
    let fresh = net.devs[0]
        .create(ObjectType::new("note"), b"org".to_vec())
        .unwrap();
    assert_eq!(fresh.body.scope.as_str(), ORG.as_str());
    let ids = net.devs[0]
        .store()
        .scope_ids(&Scope::parse(&ORG).unwrap())
        .unwrap();
    assert!(!ids.contains(&note.change_id) && ids.contains(&fresh.change_id));
}

// ---- subgroups (phase 6b-2) ----

fn finance() -> Scope {
    Scope::subgroup(&DeviceId::from_hex(&ORG).unwrap(), "finance").unwrap()
}

fn stored_in(net: &Net, who: usize, c: &Change) -> bool {
    net.devs[who].store().contains(&c.change_id).unwrap()
}

/// `members` join subgroup "finance" created by device 0.
fn with_finance(net: &mut Net, members: &[usize]) {
    let hexes: Vec<String> = members.iter().map(|&i| hex(&net.devs[i])).collect();
    let frames = net.devs[0]
        .create_subgroup(&ORG, "finance", &hexes)
        .unwrap();
    net.send(0, frames);
    for &i in members {
        assert_eq!(
            net.devs[i].my_subgroups(&ORG),
            vec!["finance".to_string()],
            "device {i}"
        );
    }
}

/// req: REQ-PERM-003
#[test]
fn subgroup_data_reaches_only_its_members() {
    let mut net = Net::org(3);
    with_finance(&mut net, &[1]);
    assert!(net.devs[2].my_subgroups(&ORG).is_empty());
    assert_eq!(
        net.devs[2].subgroup_members(&ORG, "finance").unwrap().len(),
        2
    );
    // The owner writes; member 1 reads it, device 2 cannot even decrypt it.
    let ledger = net.devs[0]
        .create_in(finance(), ObjectType::new("ledger"), b"salary".to_vec())
        .unwrap();
    let events = spread(&mut net, 0, &ledger);
    assert_eq!(received_by(&events, 1), 1);
    assert!(stored_in(&net, 1, &ledger));
    assert!(!stored_in(&net, 2, &ledger));
    // Member 1 writes back; device 2 can neither write nor read.
    let reply = net.devs[1]
        .edit(ledger.body.object_id, b"approved".to_vec())
        .unwrap();
    let events = spread(&mut net, 1, &reply);
    assert_eq!(received_by(&events, 0), 1);
    assert!(!stored_in(&net, 2, &reply));
    assert!(matches!(
        net.devs[2].create_in(finance(), ObjectType::new("ledger"), vec![]),
        Err(ClientError::Forbidden(_))
    ));
    // Catch-up in the org never carries subgroup data to device 2.
    let f = net.devs[2].sync_request_frame(&ORG).unwrap();
    net.send(2, vec![f]);
    assert!(!stored_in(&net, 2, &ledger));
}

/// req: REQ-PERM-003
#[test]
fn a_late_member_gets_the_subgroup_history() {
    let mut net = Net::org(3);
    with_finance(&mut net, &[]);
    let before = net.devs[0]
        .create_in(finance(), ObjectType::new("ledger"), b"q1".to_vec())
        .unwrap();
    spread(&mut net, 0, &before);
    let d2 = hex(&net.devs[2]);
    let frames = net.devs[0]
        .set_subgroup_members(&ORG, "finance", &[d2])
        .unwrap();
    net.send(0, frames);
    assert_eq!(net.devs[2].my_subgroups(&ORG), vec!["finance".to_string()]);
    assert!(stored_in(&net, 2, &before), "history arrives on joining");
    assert!(!stored_in(&net, 1, &before));
    // Later catch-ups include the subgroup too.
    let more = net.devs[0]
        .create_in(finance(), ObjectType::new("ledger"), b"q2".to_vec())
        .unwrap();
    let _ = more;
    let frames = net.devs[2].sync_request_frames(&ORG).unwrap();
    assert_eq!(frames.len(), 2, "org + finance");
    net.send(2, frames);
    assert!(stored_in(&net, 2, &more));
}

/// req: REQ-PERM-003
#[test]
fn removed_subgroup_members_lose_read_and_write_access() {
    let mut net = Net::org(2);
    with_finance(&mut net, &[1]);
    let theirs = net.devs[1]
        .create_in(finance(), ObjectType::new("ledger"), b"mine".to_vec())
        .unwrap();
    spread(&mut net, 1, &theirs);
    // Removed: the owner takes it out of the MLS group (keys rotate).
    let frames = net.devs[0]
        .set_subgroup_members(&ORG, "finance", &[])
        .unwrap();
    let events = net.send(0, frames);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::GroupChanged { removed: true, .. }))
    );
    assert!(net.devs[1].my_subgroups(&ORG).is_empty());
    // New subgroup data does not reach it...
    let after = net.devs[0]
        .create_in(finance(), ObjectType::new("ledger"), b"after".to_vec())
        .unwrap();
    spread(&mut net, 0, &after);
    assert!(!stored_in(&net, 1, &after));
    // ...it cannot write there any more, and its earlier change still counts.
    assert!(
        net.devs[1]
            .create_in(finance(), ObjectType::new("ledger"), vec![])
            .is_err()
    );
    assert_eq!(
        net.devs[0].history(&theirs.body.object_id).unwrap().len(),
        1
    );
    // Only admins manage subgroups.
    assert!(
        net.devs[1]
            .set_subgroup_members(&ORG, "finance", &[])
            .is_err()
    );
}

// ---- files (phase 7b) ----

fn big(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// req: REQ-FILE-001
/// req: REQ-FILE-002
#[test]
fn files_arrive_lazily_in_verified_chunks() {
    let mut net = Net::org(2);
    let data = big(600 * 1024);
    let file = net.devs[0]
        .add_file("video.mp4", "video/mp4", &data)
        .unwrap();
    let oid = file.body.object_id;
    spread(&mut net, 0, &file);
    // Only the reference travelled: device 1 knows the file but has no chunks yet.
    let info = net.devs[1].file_info(&oid).unwrap();
    assert_eq!(
        (info.name.as_str(), info.size, info.chunks, info.missing),
        ("video.mp4", data.len() as u64, 3, 3)
    );
    assert!(matches!(
        net.devs[1].read_file(&oid),
        Err(ClientError::FileIncomplete(3))
    ));
    // It asks; a peer serves; the file is complete.
    let frames = net.devs[1].fetch_file_frames(&ORG, &oid).unwrap();
    let events = net.send(1, frames);
    assert!(events.iter().any(
        |(i, e)| *i == 1 && matches!(e, Event::FileChunks { ready, .. } if ready == &vec![oid])
    ));
    assert_eq!(net.devs[1].read_file(&oid).unwrap(), data);
    assert!(
        net.devs[1]
            .fetch_file_frames(&ORG, &oid)
            .unwrap()
            .is_empty(),
        "nothing left to fetch"
    );
}

/// req: REQ-FILE-002
#[test]
fn eager_devices_fetch_files_as_they_arrive() {
    let mut net = Net::org(2);
    net.devs[1].set_fetch_files(true);
    let data = big(10_000);
    let file = net.devs[0].add_file("a.txt", "text/plain", &data).unwrap();
    let events = spread(&mut net, 0, &file);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::FileChunks { stored: 1, .. }))
    );
    assert_eq!(net.devs[1].read_file(&file.body.object_id).unwrap(), data);
}

/// req: REQ-FILE-002
/// req: REQ-PERM-003
#[test]
fn subgroup_files_stay_in_the_subgroup_and_peers_without_chunks_say_so() {
    let mut net = Net::org(3);
    with_finance(&mut net, &[1]);
    let data = big(5_000);
    let file = net.devs[0]
        .add_file_in(finance(), "q3.pdf", "application/pdf", &data)
        .unwrap();
    let oid = file.body.object_id;
    spread(&mut net, 0, &file);
    // Device 2 never sees the reference, and asking for the chunk IDs in the org
    // scope gets nothing: chunks are served only within their scope.
    assert!(net.devs[2].file_info(&oid).is_err());
    let ids = net.devs[1].missing_chunks(&oid).unwrap();
    let body = net.devs[2]
        .app_body(&ORG, &sync::chunk_want_bodies(&ids)[0])
        .unwrap();
    let from = hex(&net.devs[2]);
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert!(matches!(
        h.event,
        Event::ChunksServed {
            sent: 0,
            missing: 1,
            ..
        }
    ));
    // Member 1 fetches it from the subgroup.
    let frames = net.devs[1].fetch_file_frames(&ORG, &oid).unwrap();
    net.send(1, frames);
    assert_eq!(net.devs[1].read_file(&oid).unwrap(), data);
    // A peer that lacks the chunks says so: device 0 asks device 1 for a file whose
    // chunks only device 0 has.
    let only0 = net.devs[0].add_file("x", "x", &big(10)).unwrap();
    spread(&mut net, 0, &only0);
    let wanted = net.devs[1].missing_chunks(&only0.body.object_id).unwrap();
    let body = net.devs[0]
        .app_body(&ORG, &sync::chunk_want_bodies(&wanted)[0])
        .unwrap();
    let from = hex(&net.devs[0]);
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert!(matches!(
        h.event,
        Event::ChunksServed {
            sent: 0,
            missing: 1,
            ..
        }
    ));
}

/// req: REQ-FILE-001
#[test]
fn tampered_chunks_are_not_stored() {
    let mut net = Net::org(2);
    let file = net.devs[0].add_file("t", "t", &big(1000)).unwrap();
    let oid = file.body.object_id;
    spread(&mut net, 0, &file);
    net.devs[1].fetch_file_frames(&ORG, &oid).unwrap();
    let id = net.devs[1].missing_chunks(&oid).unwrap()[0];
    let body = net.devs[0]
        .app_body(
            &ORG,
            &sync::chunks_bodies(&[(id, b"not the chunk".to_vec())])[0],
        )
        .unwrap();
    let from = hex(&net.devs[0]);
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert!(matches!(h.event, Event::FileChunks { stored: 0, .. }));
    assert_eq!(net.devs[1].missing_chunks(&oid).unwrap().len(), 1);
}

/// req: REQ-FILE-002
#[test]
fn a_peer_without_the_chunks_makes_the_client_ask_the_author() {
    let mut net = Net::org(3);
    let data = big(3_000);
    let file = net.devs[0].add_file("f", "f", &data).unwrap();
    let oid = file.body.object_id;
    spread(&mut net, 0, &file);
    // Device 1 wants the file; suppose the relay hands its request to device 2,
    // which is lazy and has none of it.
    let _ = net.devs[1].fetch_file_frames(&ORG, &oid).unwrap();
    let ids = net.devs[1].missing_chunks(&oid).unwrap();
    let body = net.devs[1]
        .app_body(&ORG, &sync::chunk_want_bodies(&ids)[0])
        .unwrap();
    let from = hex(&net.devs[1]);
    let h = net.devs[2]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert!(matches!(
        h.event,
        Event::ChunksServed {
            sent: 0,
            missing: 1,
            ..
        }
    ));
    // Device 2's "missing" reaches device 1, which asks the author (device 0) directly.
    let events = net.send(2, h.replies);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::ChunksMissing { .. }))
    );
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::ChunksServed { sent: 1, .. }))
    );
    assert!(events.iter().any(
        |(i, e)| *i == 1 && matches!(e, Event::FileChunks { ready, .. } if ready == &vec![oid])
    ));
    assert_eq!(net.devs[1].read_file(&oid).unwrap(), data);
}

// ---- abuse limits (phase 8a) ----

/// req: REQ-RELAY-006
#[test]
fn a_misbehaving_member_cannot_fill_our_storage() {
    let mut net = Net::org(2);
    let d1 = hex(&net.devs[1]);
    let demote = net.devs[0].set_role(&ORG, &d1, Role::Viewer).unwrap();
    spread(&mut net, 0, &demote);
    let before = net.devs[0].store().all_ids().unwrap().len();
    for _ in 0..MAX_QUARANTINE + 10 {
        let c = forged(&net, 1, "note", vec![], ObjectId::random());
        let _ = net.devs[0].receive(c);
    }
    let after = net.devs[0].store().all_ids().unwrap().len();
    assert_eq!(
        after - before,
        MAX_QUARANTINE,
        "kept up to the cap, then dropped"
    );
    // The cap survives a restart (counts are rebuilt from the store).
    let old = std::mem::replace(&mut net.devs[0], client());
    let key = DeviceKey::from_secret_bytes(&old.signer().secret_bytes());
    let Client { store, .. } = old;
    net.devs[0] = Client::new(key, store).unwrap();
    let c = forged(&net, 1, "note", vec![], ObjectId::random());
    let _ = net.devs[0].receive(c.clone());
    assert!(!net.devs[0].store().contains(&c.change_id).unwrap());
}

// ---- backups (phase 8b) ----

/// req: REQ-DATA-006
#[test]
fn a_device_restored_from_a_backup_rejoins_and_catches_up() {
    let mut net = Net::org(2);
    let note = net.create(1, b"mine");
    let file = net.devs[1].add_file("f", "f", &big(2000)).unwrap();
    spread(&mut net, 1, &file);
    let backup = net.devs[1].export_backup("correct horse").unwrap();
    assert!(!backup.windows(4).any(|w| w == b"mine"), "encrypted");
    assert!(matches!(
        Client::import_backup(&backup, "wrong", MemoryStore::new()),
        Err(ClientError::InvalidBackup(_))
    ));
    // Device 1 is lost; the org goes on without it.
    net.offline.insert(1);
    let later = net.create(0, b"while it was gone");
    // Restored on new hardware: same identity and data, but no MLS keys yet.
    net.devs[1] = Client::import_backup(&backup, "correct horse", MemoryStore::new()).unwrap();
    net.offline.clear();
    let d = &net.devs[1];
    assert!(d.store().contains(&note.change_id).unwrap());
    assert_eq!(d.read_file(&file.body.object_id).unwrap(), big(2000));
    assert!(!d.is_member(&ORG));
    assert!(!d.membership_proof(&ORG).is_empty(), "still certified");
    // Seeing a peer online, it asks to be re-added, rejoins and catches up.
    let online = vec![hex(&net.devs[0]), hex(&net.devs[1])];
    let h = net.devs[1]
        .handle_frame(Frame::Presence {
            org: ORG.clone(),
            online,
        })
        .unwrap();
    assert_eq!(h.replies.len(), 1);
    let events = net.send(1, h.replies);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::MemberReAdded { .. }))
    );
    assert!(net.devs[1].is_member(&ORG));
    assert!(net.devs[1].store().contains(&later.change_id).unwrap());
    // And it works normally again.
    let c = net.devs[1]
        .create(ObjectType::new("note"), b"back".to_vec())
        .unwrap();
    let events = spread(&mut net, 1, &c);
    assert_eq!(received_by(&events, 0), 1);
    assert!(Client::import_backup(b"garbage", "x", MemoryStore::new()).is_err());
}

/// req: REQ-ID-002
#[test]
fn a_member_adds_its_own_device_and_it_follows_the_member() {
    let mut net = Net::org(2); // 0 = admin, 1 = plain member
    net.devs.push(client());
    let org = DeviceId::from_hex(&ORG).unwrap();
    // Admins cannot be linked to by accident, and strangers cannot make links.
    assert!(
        net.devs[2]
            .create_own_device_invite(&ORG, "ws://relay/v1/ws", 60_000)
            .is_err(),
        "not a member yet"
    );
    // Member 1 (not an admin) links device 2.
    let link = net.devs[1]
        .create_own_device_invite(&ORG, "ws://relay/v1/ws", 60_000)
        .unwrap();
    let claim = net.devs[2].claim_invite(&link).unwrap();
    assert!(
        matches!(&claim.frame, Frame::InviteClaim { to: Some(t), .. } if *t == hex(&net.devs[1]))
    );
    let events = net.send(2, vec![claim.frame]);
    let code = events
        .iter()
        .find_map(|(i, e)| match e {
            Event::InviteClaimed { code, .. } if *i == 1 => Some(code.clone()),
            _ => None,
        })
        .expect("the claim reaches the member, not an admin");
    assert_eq!(code, claim.code);
    assert!(
        !events
            .iter()
            .any(|(i, e)| *i == 0 && matches!(e, Event::InviteClaimed { .. })),
        "the admin does not see it"
    );
    let phone = hex(&net.devs[2]);
    let frames = net.devs[1].accept_claim(&ORG, &phone).unwrap();
    let events = net.send(1, frames);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::Joined { .. }))
    );
    assert!(net.devs[2].is_member(&ORG));
    // Its chain has three certificates and the relay accepts it, without admin rights.
    let chain = CertChain::from_hex(&net.devs[2].membership_proof(&ORG)).unwrap();
    assert_eq!(chain.0.len(), 3);
    assert!(chain.0[2].own);
    assert!(!chain.verify(&org, &net.devs[2].device_id()).unwrap().admin);
    assert!(!net.devs[2].is_admin(&ORG));
    // Every device's policy says it belongs to member 1 and has its role.
    for d in &net.devs {
        let p = d.policy(&ORG).unwrap();
        assert_eq!(
            p.links.get(&net.devs[2].device_id()),
            Some(&net.devs[1].device_id())
        );
    }
    assert_eq!(
        net.devs[0].role_of(&ORG, &phone).unwrap(),
        Some(Role::Editor)
    );
    // The linked device cannot link or admit devices itself.
    assert!(
        net.devs[2]
            .create_own_device_invite(&ORG, "ws://relay/v1/ws", 60_000)
            .is_err()
    );
    // Both devices write; the admin sees both.
    let c = net.create(2, b"from the phone");
    assert!(
        net.devs[0]
            .history(&c.body.object_id)
            .is_ok_and(|h| h.len() == 1)
    );
    // Demoting the member demotes the phone; removing it removes the phone from the
    // group and revokes it.
    let member = hex(&net.devs[1]);
    let frames = net.devs[0].remove_member(&ORG, &member).unwrap();
    net.send(0, frames);
    assert_eq!(net.devs[0].role_of(&ORG, &phone).unwrap(), None);
    let members = net.devs[0].group_members(&ORG).unwrap();
    assert_eq!(members, vec![hex(&net.devs[0])]);
}

/// req: REQ-ID-002
#[test]
fn an_own_device_invite_cannot_be_accepted_by_someone_else() {
    let mut net = Net::org(3);
    net.devs.push(client());
    let link = net.devs[1]
        .create_own_device_invite(&ORG, "ws://relay/v1/ws", 60_000)
        .unwrap();
    let claim = net.devs[3].claim_invite(&link).unwrap();
    net.send(3, vec![claim.frame]);
    // Device 2 never saw the claim, so it has nothing to accept.
    let new = hex(&net.devs[3]);
    assert!(net.devs[2].accept_claim(&ORG, &new).is_err());
    assert!(!net.devs[3].is_member(&ORG));
}

/// req: REQ-DATA-007
#[test]
fn objects_lists_what_the_device_knows() {
    let mut c = client();
    assert!(c.objects(None).unwrap().is_empty());
    let note = c
        .create(ObjectType::new("acme.note"), b"a".to_vec())
        .unwrap();
    c.edit(note.body.object_id, b"b".to_vec()).unwrap();
    let todo = c
        .create(ObjectType::new("acme.todo"), b"x".to_vec())
        .unwrap();
    let all = c.objects(None).unwrap();
    // One entry per object (not per change), creation changes only.
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|c| c.is_creation()));
    let notes = c.objects(Some("acme.note")).unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].body.object_id, note.body.object_id);
    assert_eq!(
        c.objects(Some("acme.todo")).unwrap()[0].body.object_id,
        todo.body.object_id
    );
    assert!(c.objects(Some("nope")).unwrap().is_empty());
}

/// req: REQ-PERM-001
#[test]
fn the_root_holder_upgrades_an_older_policy_on_start() {
    let mut net = Net::org(2);
    let (d0, d1) = (net.devs[0].device_id(), net.devs[1].device_id());
    // Rebuild device 0's store as an older version left it: a genesis signed by
    // the device itself, and member 1 not named in the policy.
    let old = std::mem::replace(&mut net.devs[0], client());
    let key = DeviceKey::from_secret_bytes(&old.signer().secret_bytes());
    let org_id = DeviceId::from_hex(&ORG).unwrap();
    let root = DeviceKey::from_secret_bytes(&ROOT_SECRET);
    let mut store = MemoryStore::new();
    for meta in [MLS_STATE_KEY, ORGS_KEY] {
        let v = old.store().get_meta(meta).unwrap().unwrap();
        store.put_meta(meta, &v).unwrap();
    }
    let genesis = Change::sign(
        UnsignedChange {
            scope: Scope::org(&org_id),
            object_id: policy_object_id(&org_id),
            object_type: ObjectType::new(POLICY_TYPE),
            parents: vec![],
            timestamp_ms: 1,
            payload: PolicyOp::Genesis {
                admin: MembershipCert::issue(&root, org_id, d0, true, 1),
            }
            .encode(),
        },
        &key,
    );
    store.put(genesis).unwrap();
    net.devs[0] = Client::new(key, store).unwrap();
    let p = net.devs[0].policy(&ORG).unwrap();
    assert_eq!(p.creator, Some(d0));
    assert_eq!(p.role_of(&d1), Some(Role::Editor), "group member named");
    assert!(net.devs[0].is_admin(&ORG));
}

/// req: REQ-PERM-002
#[test]
fn policy_changes_by_members_are_not_kept() {
    let mut net = Net::org(2);
    let org_id = DeviceId::from_hex(&ORG).unwrap();
    let pid = policy_object_id(&org_id);
    let sneaky = Change::sign(
        UnsignedChange {
            scope: Scope::org(&org_id),
            object_id: pid,
            object_type: ObjectType::new(POLICY_TYPE),
            parents: net.devs[1].store().heads(&pid).unwrap(),
            timestamp_ms: 1,
            payload: PolicyOp::SetRule {
                object_type: "note".into(),
                write: Role::Viewer,
            }
            .encode(),
        },
        net.devs[1].signer(),
    );
    assert!(matches!(
        net.devs[0].receive(sneaky.clone()),
        Err(ClientError::Forbidden(_))
    ));
    assert!(
        net.devs[0]
            .store()
            .get(&sneaky.change_id)
            .unwrap()
            .is_none()
    );
    // A key the policy does not name cannot write either.
    let stranger = client();
    let note = stranger.signer();
    let c = Change::sign(
        UnsignedChange {
            scope: Scope::org(&org_id),
            object_id: ObjectId::random(),
            object_type: ObjectType::new("note"),
            parents: vec![],
            timestamp_ms: 1,
            payload: b"x".to_vec(),
        },
        note,
    );
    assert!(matches!(
        net.devs[0].receive(c),
        Err(ClientError::Forbidden(_))
    ));
}

// ---- Welcome checks (ADR 0016) ----

fn welcome_to(
    net: &mut Net,
    victim: usize,
    from: &str,
    welcome: Vec<u8>,
    chain: String,
) -> Handled {
    net.devs[victim]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: from.into(),
            body: sync::outer_body(&Outer::Welcome { welcome, chain }),
        })
        .unwrap()
}

/// req: REQ-ENC-001
#[test]
fn outsiders_cannot_ask_for_a_key_package() {
    let mut net = Net::org(2);
    let outsider = hex(&client());
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: outsider,
            body: sync::outer_body(&Outer::ReaddNeeded { group: ORG.clone() }),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert!(h.replies.is_empty(), "no KeyPackage leaves");
}

/// req: REQ-ENC-001
#[test]
fn an_unrequested_welcome_does_not_replace_the_group() {
    let mut net = Net::org(2);
    let victim = 1;
    let mut atk = client();
    let atk_hex = hex(&atk);
    atk.groups.create_group(&atk.key, &ORG).unwrap();
    // Even with one of the victim's KeyPackages (however obtained).
    let v = &mut net.devs[victim];
    let kp = v.groups.key_package(&v.key).unwrap();
    let added = atk.groups.add_member(&atk.key, &ORG, &kp).unwrap();
    let before = net.devs[victim].group_members(&ORG).unwrap();
    let h = welcome_to(&mut net, victim, &atk_hex, added.welcome, String::new());
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert_eq!(net.devs[victim].group_members(&ORG).unwrap(), before);
    // The victim's next write stays unreadable for the attacker.
    let c = net.devs[victim]
        .create(ObjectType::new("note"), b"secret".to_vec())
        .unwrap();
    let Frame::Broadcast { body, .. } = net.devs[victim].broadcast_frame(&ORG, &c).unwrap() else {
        panic!("broadcast expected")
    };
    let Ok(Outer::App(ct)) = sync::parse_outer(&body) else {
        panic!("app message expected")
    };
    assert!(atk.groups.decrypt(&ORG, &ct).is_err());
}

/// req: REQ-ENC-004
#[test]
fn a_requested_welcome_must_not_add_outsiders() {
    let mut net = Net::org(3);
    let (victim, peer) = (1, 2);
    let peer_hex = hex(&net.devs[peer]);
    // The victim asks member 2 to re-add it (as after a lost fork)...
    let frame = net.devs[victim]
        .readd_request_frame(&ORG, &ORG, &peer_hex)
        .unwrap();
    let Frame::Direct { body, .. } = frame else {
        panic!("direct expected")
    };
    let Ok(Outer::KeyPackage { key_package, .. }) = sync::parse_outer(&body) else {
        panic!("KeyPackage expected")
    };
    // ...and member 2 answers with a group of its own that includes an outsider.
    let mut outsider = client();
    let outsider_kp = outsider.groups.key_package(&outsider.key).unwrap();
    let mut rogue = Groups::new();
    rogue.create_group(&net.devs[peer].key, &ORG).unwrap();
    rogue
        .add_member(&net.devs[peer].key, &ORG, &outsider_kp)
        .unwrap();
    let added = rogue
        .add_member(&net.devs[peer].key, &ORG, &key_package)
        .unwrap();
    let before = net.devs[victim].group_members(&ORG).unwrap();
    let h = welcome_to(&mut net, victim, &peer_hex, added.welcome, String::new());
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert_eq!(net.devs[victim].group_members(&ORG).unwrap(), before);
}

/// req: REQ-INV-002
#[test]
fn a_first_welcome_needs_the_adders_certificate() {
    let mut net = Net::org(2);
    let mut newbie = client();
    let link = net.devs[0]
        .create_invite(&ORG, "ws://relay/v1/ws", 60_000)
        .unwrap();
    let _claim = newbie.claim_invite(&link).unwrap();
    // Member 1 (not the admin) adds the newcomer to a group it made, with a chain
    // that does not prove the newcomer.
    let kp = newbie.groups.key_package(&newbie.key).unwrap();
    let mut rogue = Groups::new();
    rogue.create_group(&net.devs[1].key, &ORG).unwrap();
    let added = rogue.add_member(&net.devs[1].key, &ORG, &kp).unwrap();
    let chain = net.devs[1].membership_proof(&ORG);
    net.devs.push(newbie);
    let from = hex(&net.devs[1]);
    let h = welcome_to(&mut net, 2, &from, added.welcome, chain);
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert!(!net.devs[2].is_member(&ORG));
}

// ---- commit authorization (ADR 0017) ----

/// req: REQ-ENC-001
/// req: REQ-PERM-002
#[test]
fn an_editor_cannot_add_or_remove_devices() {
    let mut net = Net::org(3);
    let before = net.devs[0].group_members(&ORG).unwrap();
    let editor_hex = hex(&net.devs[1]);
    // Editor 1 adds an outsider to the group...
    let mut outsider = client();
    let kp = outsider.groups.key_package(&outsider.key).unwrap();
    let e = &mut net.devs[1];
    let added = e.groups.add_member(&e.key, &ORG, &kp).unwrap();
    for i in [0, 2] {
        let h = net.devs[i]
            .handle_frame(Frame::Deliver {
                org: ORG.clone(),
                from: editor_hex.clone(),
                body: sync::outer_body(&Outer::Commit(added.commit.clone())),
            })
            .unwrap();
        assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
        assert_eq!(net.devs[i].group_members(&ORG).unwrap(), before);
    }
    // ...or removes the admin (on a fresh copy of the group state).
    let mut net = Net::org(3);
    let admin = net.devs[0].device_id();
    let e = &mut net.devs[1];
    let commit = e.groups.remove_member(&e.key, &ORG, admin).unwrap();
    let h = net.devs[2]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: editor_hex,
            body: sync::outer_body(&Outer::Commit(commit)),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert_eq!(net.devs[2].group_members(&ORG).unwrap().len(), 3);
}

/// req: REQ-ENC-001
#[test]
fn a_commit_must_come_from_its_sender() {
    let mut net = Net::org(3);
    let a = &mut net.devs[0];
    let commit = a.groups.self_update(&a.key, &ORG).unwrap();
    let epoch = net.devs[2].group_epoch(&ORG).unwrap();
    // The relay claims member 1 sent the admin's commit.
    let from = hex(&net.devs[1]);
    let h = net.devs[2]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body: sync::outer_body(&Outer::Commit(commit)),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert_eq!(net.devs[2].group_epoch(&ORG).unwrap(), epoch);
}

/// req: REQ-ENC-004
#[test]
fn a_readd_for_another_device_changes_nothing() {
    let mut net = Net::org(3);
    let epoch = net.devs[0].group_epoch(&ORG).unwrap();
    // Member 1 sends member 2's KeyPackage as if it lost the group.
    let d2 = &mut net.devs[2];
    let kp = d2.groups.key_package(&d2.key).unwrap();
    let from = hex(&net.devs[1]);
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body: sync::outer_body(&Outer::KeyPackage {
                group: ORG.clone(),
                key_package: kp,
            }),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert!(h.replies.is_empty());
    assert_eq!(net.devs[0].group_epoch(&ORG).unwrap(), epoch);
}

/// req: REQ-ENC-002
#[test]
fn outsiders_get_no_commits() {
    let mut net = Net::org(2);
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: hex(&client()),
            body: sync::outer_body(&Outer::CommitRequest {
                group: ORG.clone(),
                epoch: 0,
            }),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert!(h.replies.is_empty());
}

// ---- claim channel and relay notices (ADR 0018) ----

/// req: REQ-INV-002
#[test]
fn claims_and_other_messages_keep_to_their_frames() {
    let mut net = Net::org(2);
    let outsider = hex(&client());
    // A claim frame carrying anything but a claim is refused...
    let h = net.devs[1]
        .handle_frame(Frame::ClaimDeliver {
            org: ORG.clone(),
            from: outsider.clone(),
            body: sync::outer_body(&Outer::ReaddNeeded { group: ORG.clone() }),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
    assert!(h.replies.is_empty());
    // ...and so is a claim in an ordinary delivery.
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: outsider,
            body: sync::outer_body(&Outer::Claim {
                token: [0; 16],
                proof: [0; 32],
                key_package: vec![],
            }),
        })
        .unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }), "{:?}", h.event);
}

/// req: REQ-INV-004
#[test]
fn the_root_holder_signs_relay_notices_with_the_root_key() {
    let mut net = Net::org(2);
    let gone = hex(&net.devs[1]);
    net.devs[0].remove_member(&ORG, &gone).unwrap();
    let notice = net.devs[0].revocations.last().unwrap();
    assert!(notice.by_root());
    notice.verify(&DeviceId::from_hex(&ORG).unwrap()).unwrap();
}
