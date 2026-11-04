use std::collections::{BTreeSet, VecDeque};

use kith_protocol::Frame;

use super::*;

const ORG: &str = "org";

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
                _ => continue,
            };
            for t in targets {
                let handled = self.devs[t]
                    .handle_frame(Frame::Deliver {
                        org: ORG.into(),
                        from: from_hex.clone(),
                        body: body.clone(),
                    })
                    .unwrap();
                self.events.push((t, handled.event));
                queue.extend(handled.replies.into_iter().map(|f| (t, f)));
            }
        }
        self.events.drain(start..).collect()
    }

    /// Device 0 creates the group, the others ask it to join and it admits them.
    fn org(n: usize) -> Self {
        let mut net = Self::new(n);
        net.devs[0].create_group(ORG).unwrap();
        for i in 1..n {
            net.admit(0, i);
        }
        net
    }

    fn admit(&mut self, admin: usize, new: usize) {
        let to = hex(&self.devs[admin]);
        let req = self.devs[new].join_request_frame(ORG, &to).unwrap();
        let events = self.send(new, vec![req]);
        let kp = events
            .into_iter()
            .find_map(|(i, e)| match e {
                Event::JoinRequested { key_package, .. } if i == admin => Some(key_package),
                _ => None,
            })
            .expect("join request reaches the admin");
        let frames = self.devs[admin].add_member(ORG, &kp).unwrap();
        let events = self.send(admin, frames);
        assert!(
            events
                .iter()
                .any(|(i, e)| *i == new && matches!(e, Event::Joined { .. }))
        );
        assert!(self.devs[new].is_member(ORG));
    }

    fn create(&mut self, who: usize, payload: &[u8]) -> Change {
        let c = self.devs[who]
            .create(ObjectType::new("note"), payload.to_vec())
            .unwrap();
        let f = self.devs[who].broadcast_frame(ORG, &c).unwrap();
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
    let frame = net.devs[1].broadcast_frame(ORG, &c).unwrap();
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
    let c = outsider
        .create(ObjectType::new("note"), b"x".to_vec())
        .unwrap();
    // No group: an outsider cannot even produce a broadcast.
    assert!(matches!(
        outsider.broadcast_frame(ORG, &c),
        Err(ClientError::Group(_))
    ));
    // The pre-MLS plaintext body is refused.
    let plain = Frame::Deliver {
        org: ORG.into(),
        from: hex(&outsider),
        body: sync::change_body(&c),
    };
    let h = net.devs[0].handle_frame(plain).unwrap();
    assert!(matches!(h.event, Event::Rejected { .. }));
    assert!(!net.devs[0].store().contains(&c.change_id).unwrap());
    // An outsider with its own group of the same name cannot write into ours.
    outsider.create_group(ORG).unwrap();
    let frame = outsider.broadcast_frame(ORG, &c).unwrap();
    let Frame::Broadcast { body, .. } = frame else {
        panic!()
    };
    let h = net.devs[0]
        .handle_frame(Frame::Deliver {
            org: ORG.into(),
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
    let Frame::Broadcast { body, .. } = net.devs[1].broadcast_frame(ORG, &c).unwrap() else {
        panic!()
    };
    let spoofed = Frame::Deliver {
        org: ORG.into(),
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
    let f = net.devs[0].remove_member(ORG, &removed).unwrap();
    let events = net.send(0, vec![f]);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 2 && matches!(e, Event::GroupChanged { removed: true, .. }))
    );
    assert!(!net.devs[2].is_member(ORG));
    let events = {
        let c = net.devs[0]
            .create(ObjectType::new("note"), b"after".to_vec())
            .unwrap();
        let f = net.devs[0].broadcast_frame(ORG, &c).unwrap();
        net.send(0, vec![f])
    };
    assert_eq!(received_by(&events, 1), 1);
    assert_eq!(received_by(&events, 2), 0);
    assert_eq!(net.devs[1].group_members(ORG).unwrap().len(), 2);
}

/// req: REQ-ENC-002
/// req: REQ-ENC-003
#[test]
fn device_that_missed_commits_catches_up_and_gets_the_data() {
    let mut net = Net::org(3);
    net.offline.insert(2);
    for who in [0, 1] {
        let f = net.devs[who].rotate_key(ORG).unwrap();
        net.send(who, vec![f]);
    }
    let missed = net.create(1, b"while you were away");
    net.offline.clear();
    assert!(net.devs[2].group_epoch(ORG).unwrap() < net.devs[0].group_epoch(ORG).unwrap());

    // The next broadcast is from an epoch device 2 has not reached.
    let events = {
        let c = net.devs[0]
            .create(ObjectType::new("note"), b"now".to_vec())
            .unwrap();
        let f = net.devs[0].broadcast_frame(ORG, &c).unwrap();
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
        net.devs[2].group_epoch(ORG).unwrap(),
        net.devs[0].group_epoch(ORG).unwrap()
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
    let f = net.devs[0].rotate_key(ORG).unwrap();
    net.send(0, vec![f]);
    net.offline.clear();
    // Device 1 broadcasts from its old epoch; device 0 still reads it (past epoch
    // keys) and sends device 1 the commit.
    let c = net.devs[1]
        .create(ObjectType::new("note"), b"old epoch".to_vec())
        .unwrap();
    let f = net.devs[1].broadcast_frame(ORG, &c).unwrap();
    let events = net.send(1, vec![f]);
    assert_eq!(received_by(&events, 0), 1);
    assert!(
        events
            .iter()
            .any(|(i, e)| *i == 1 && matches!(e, Event::CommitsApplied { applied: 1, .. }))
    );
    assert_eq!(
        net.devs[1].group_epoch(ORG).unwrap(),
        net.devs[0].group_epoch(ORG).unwrap()
    );
}

/// req: REQ-ENC-004
#[test]
fn device_beyond_the_commit_log_is_readded_automatically() {
    let mut net = Net::org(3);
    net.offline.insert(2);
    for _ in 0..kith_crypto::group::COMMIT_LOG_LEN + 1 {
        let f = net.devs[0].rotate_key(ORG).unwrap();
        net.send(0, vec![f]);
    }
    let missed = net.create(0, b"far away");
    net.offline.clear();
    let f = net.devs[2].sync_request_frame(ORG).unwrap();
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
    assert_eq!(net.devs[1].group_members(ORG).unwrap().len(), 3);
    // And it can talk again.
    let events = {
        let c = net.devs[2]
            .create(ObjectType::new("note"), b"back".to_vec())
            .unwrap();
        let f = net.devs[2].broadcast_frame(ORG, &c).unwrap();
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
    assert!(net.devs[1].is_member(ORG));
    let events = {
        let c = net.devs[1]
            .create(ObjectType::new("note"), b"after".to_vec())
            .unwrap();
        let f = net.devs[1].broadcast_frame(ORG, &c).unwrap();
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
    net.devs[0].create_group(ORG).unwrap();
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

    let f = net.devs[1].sync_request_frame(ORG).unwrap();
    let events: Vec<Event> = net.send(1, vec![f]).into_iter().map(|(_, e)| e).collect();
    assert_eq!(net.ids(0), net.ids(1));
    assert_eq!(net.ids(0).len(), 3);
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
    let mut net = Net::org(2);
    net.create(0, b"v");
    let f = net.devs[1].sync_request_frame(ORG).unwrap();
    let events: Vec<Event> = net.send(1, vec![f]).into_iter().map(|(_, e)| e).collect();
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
    let f = net.devs[1].sync_request_frame(ORG).unwrap();
    net.send(1, vec![f]);
    assert_eq!(net.ids(1), net.ids(0));
}

/// Deliver an inner message from `from` to `to`, encrypted like a real peer would.
fn deliver_inner(net: &mut Net, from: usize, to: usize, inner: &[u8]) -> Handled {
    let body = net.devs[from].app_body(ORG, inner).unwrap();
    let from_hex = hex(&net.devs[from]);
    net.devs[to]
        .handle_frame(Frame::Deliver {
            org: ORG.into(),
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
                org: ORG.into(),
                from: "x".into(),
                body,
            })
            .unwrap();
        assert!(matches!(h.event, Event::Rejected { .. }));
        assert!(h.replies.is_empty());
    }
}
