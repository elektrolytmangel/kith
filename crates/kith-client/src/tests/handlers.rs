//! Characterization tests for the two big message handlers, `handle_deliver`
//! (`frames.rs`) and `handle_plain` (`plain.rs`): the rejection and edge branches
//! the other tests do not reach. They pin the behaviour down before the handlers
//! are split into one function per message kind.
//!
//! Still not covered (needs a state the harness cannot build cheaply): a fork
//! claimed by a non-member, a Welcome with a bad certificate chain, a failing
//! re-add, and storage errors in `receive`.

use super::*;

/// The reason of a `Rejected` event; fails the test on any other event.
fn reason(h: &Handled) -> &str {
    match &h.event {
        Event::Rejected { reason, .. } => reason,
        e => panic!("expected Rejected, got {e:?}"),
    }
}

/// Deliver an outer message from `from` to device `to`, as the relay would.
fn outer(net: &mut Net, to: usize, from: &str, msg: &Outer) -> Handled {
    net.devs[to]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: from.into(),
            body: sync::outer_body(msg),
        })
        .unwrap()
}

/// An org ID that is not `ORG`.
fn other_org() -> String {
    DeviceKey::generate().device_id().to_hex()
}

// ---- handle_frame / handle_deliver (frames.rs) ----

/// req: REQ-SYNC-004
#[test]
fn relay_frames_without_a_body_become_events() {
    let mut net = Net::org(2);
    let h = net.devs[1]
        .handle_frame(Frame::Receipt {
            delivered: vec!["a".into(), "b".into()],
        })
        .unwrap();
    assert!(matches!(&h.event, Event::Receipt { delivered } if delivered.len() == 2));
    let h = net.devs[1]
        .handle_frame(Frame::Error {
            code: "rate-limited".into(),
            message: "slow down".into(),
        })
        .unwrap();
    assert!(matches!(&h.event, Event::RelayError { code, message }
        if code == "rate-limited" && message == "slow down"));
    // A frame a client never handles is ignored.
    let h = net.devs[1]
        .handle_frame(Frame::SyncRequest {
            org: ORG.clone(),
            body: vec![],
        })
        .unwrap();
    assert!(matches!(h.event, Event::Ignored));
    assert!(h.replies.is_empty());
}

/// req: REQ-INV-002
#[test]
fn claims_only_come_as_claims_and_claims_are_the_only_thing_that_does() {
    let mut net = Net::org(2);
    let from = hex(&net.devs[1]);
    let claim = Outer::Claim {
        token: [0; 16],
        proof: [0; 32],
        key_package: vec![1],
    };
    // A claim through the normal channel.
    let h = outer(&mut net, 0, &from, &claim);
    assert!(reason(&h).contains("must come as a claim"), "{h:?}");
    assert!(h.replies.is_empty());
    // Anything else through the claim channel.
    let h = net.devs[0]
        .handle_frame(Frame::ClaimDeliver {
            org: ORG.clone(),
            from,
            body: sync::outer_body(&Outer::Cert("00".into())),
        })
        .unwrap();
    assert!(reason(&h).contains("only an invite claim"), "{h:?}");
}

/// req: REQ-ENC-001
#[test]
fn app_messages_and_commits_for_another_org_are_rejected() {
    let mut net = Net::org(2);
    let mut stranger = client();
    let elsewhere = other_org();
    stranger.create_group(&elsewhere).unwrap();
    let from = hex(&stranger);
    let body = stranger.app_body(&elsewhere, &sync::more_body()).unwrap();
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: from.clone(),
            body,
        })
        .unwrap();
    assert_eq!(reason(&h), "message for another org");
    assert!(h.replies.is_empty());
    // The same for a commit of a group that is not part of this org.
    let Frame::Broadcast { body, .. } = stranger.rotate_key(&elsewhere).unwrap() else {
        panic!("rotate_key sends a broadcast")
    };
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from,
            body,
        })
        .unwrap();
    assert_eq!(reason(&h), "commit for another org");
}

/// req: REQ-ENC-001
#[test]
fn a_commit_needs_a_sender_that_is_a_device_id() {
    let mut net = Net::org(2);
    let Frame::Broadcast { body, .. } = net.devs[0].rotate_key(&ORG).unwrap() else {
        panic!("rotate_key sends a broadcast")
    };
    let epoch = net.devs[1].group_epoch(&ORG).unwrap();
    let h = net.devs[1]
        .handle_frame(Frame::Deliver {
            org: ORG.clone(),
            from: "not-a-device".into(),
            body,
        })
        .unwrap();
    assert_eq!(reason(&h), "sender is not a device ID");
    assert_eq!(net.devs[1].group_epoch(&ORG).unwrap(), epoch);
}

/// req: REQ-ENC-004
#[test]
fn messages_naming_a_group_of_another_org_are_rejected() {
    let mut net = Net::org(2);
    let from = hex(&net.devs[0]);
    let group = format!("{}/x", other_org());
    for msg in [
        Outer::KeyPackage {
            group: group.clone(),
            key_package: vec![1],
        },
        Outer::CommitRequest {
            group: group.clone(),
            epoch: 0,
        },
        Outer::Commits {
            group: group.clone(),
            commits: vec![],
        },
        Outer::ReaddNeeded {
            group: group.clone(),
        },
    ] {
        let h = outer(&mut net, 1, &from, &msg);
        assert_eq!(reason(&h), "group of another org", "{msg:?}");
        assert!(h.replies.is_empty());
    }
}

/// req: REQ-ENC-004
#[test]
fn commits_are_taken_only_from_members_and_only_when_valid() {
    let mut net = Net::org(2);
    let epoch = net.devs[1].group_epoch(&ORG).unwrap();
    // From a device that is not in the group.
    let outsider = hex(&client());
    let h = outer(
        &mut net,
        1,
        &outsider,
        &Outer::Commits {
            group: ORG.clone(),
            commits: vec![],
        },
    );
    assert_eq!(reason(&h), "not a member of this group");
    // From a member, but the commit is garbage: nothing is applied.
    let member = hex(&net.devs[0]);
    let committer = net.devs[0].device_id();
    let h = outer(
        &mut net,
        1,
        &member,
        &Outer::Commits {
            group: ORG.clone(),
            commits: vec![(committer, vec![1, 2, 3])],
        },
    );
    assert!(matches!(h.event, Event::Rejected { .. }), "{h:?}");
    assert!(h.replies.is_empty());
    assert_eq!(net.devs[1].group_epoch(&ORG).unwrap(), epoch);
}

/// req: REQ-ENC-004
#[test]
fn a_readd_request_for_a_group_we_are_not_in_is_rejected() {
    let mut net = Net::org(2);
    let from = hex(&net.devs[0]);
    let h = outer(
        &mut net,
        1,
        &from,
        &Outer::ReaddNeeded {
            group: format!("{}/nosuch", *ORG),
        },
    );
    assert_eq!(reason(&h), "not in this group");
    assert!(h.replies.is_empty());
}

/// req: REQ-ID-001
#[test]
fn an_invalid_certificate_chain_is_rejected_and_the_old_one_kept() {
    let mut net = Net::org(2);
    let from = hex(&net.devs[0]);
    let before = net.devs[1].membership_proof(&ORG);
    let h = outer(&mut net, 1, &from, &Outer::Cert("not a chain".into()));
    assert!(reason(&h).starts_with("membership certificate"), "{h:?}");
    assert_eq!(net.devs[1].membership_proof(&ORG), before);
}

/// req: REQ-INV-003
#[test]
fn a_claim_after_the_invite_expired_is_rejected() {
    let mut net = Net::new(3);
    net.devs[0].create_org_with_root_key(&ROOT_SECRET).unwrap();
    net.admit(0, 1);
    let link = net.devs[0]
        .create_invite(&ORG, "ws://relay/v1/ws", 40)
        .unwrap();
    let claim = net.devs[2].claim_invite(&link).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(80));
    let events = net.send(2, vec![claim.frame]);
    assert!(
        events.iter().any(|(i, e)| *i == 0
            && matches!(e, Event::Rejected { reason, .. } if reason == "invite expired")),
        "{events:?}"
    );
    assert!(!net.devs[2].is_member(&ORG));
}

/// req: REQ-INV-002
#[test]
fn a_claim_with_another_devices_key_package_is_rejected() {
    let mut net = Net::new(3);
    net.devs[0].create_org_with_root_key(&ROOT_SECRET).unwrap();
    net.admit(0, 1);
    let link = net.devs[0]
        .create_invite(&ORG, "ws://relay/v1/ws", 60_000)
        .unwrap();
    let claim = net.devs[2].claim_invite(&link).unwrap();
    let Frame::InviteClaim { body, .. } = claim.frame else {
        panic!("claims are invite-claim frames")
    };
    // Device 1 relays device 2's claim as its own.
    let relayer = hex(&net.devs[1]);
    let h = net.devs[0]
        .handle_frame(Frame::ClaimDeliver {
            org: ORG.clone(),
            from: relayer,
            body,
        })
        .unwrap();
    assert_eq!(reason(&h), "KeyPackage is not the sender's");
    assert!(h.replies.is_empty());
}

// ---- handle_plain (plain.rs) ----

/// req: REQ-SYNC-004
#[test]
fn a_change_seen_twice_is_new_once() {
    let mut net = Net::org(2);
    let c = net.devs[0]
        .create(ObjectType::new("note"), b"x".to_vec())
        .unwrap();
    for is_new in [true, false] {
        let h = deliver_inner(&mut net, 0, 1, &sync::change_body(&c));
        assert!(matches!(&h.event, Event::Received { is_new: n, .. } if *n == is_new));
        assert!(h.replies.is_empty());
    }
    assert!(net.devs[1].store().contains(&c.change_id).unwrap());
}

/// req: REQ-SYNC-002
#[test]
fn a_garbage_query_or_reply_is_rejected_and_ends_our_round() {
    let mut net = Net::org(2);
    let h = deliver_inner(&mut net, 0, 1, &sync::query_body(&[1, 2, 3]));
    assert!(matches!(h.event, Event::Rejected { .. }), "{h:?}");
    // A round of ours that gets a garbage answer is dropped.
    net.devs[1].sync_request_frame(&ORG).unwrap();
    assert!(net.devs[1].reconciling.contains_key(&*ORG));
    let h = deliver_inner(&mut net, 0, 1, &sync::reply_body(&[1, 2, 3]));
    assert!(matches!(h.event, Event::Rejected { .. }), "{h:?}");
    assert!(!net.devs[1].reconciling.contains_key(&*ORG));
}

/// req: REQ-SYNC-005
#[test]
fn more_starts_a_round_unless_one_is_running() {
    let mut net = Net::org(2);
    let h = deliver_inner(&mut net, 0, 1, &sync::more_body());
    assert!(matches!(h.event, Event::Ignored));
    assert_eq!(h.replies.len(), 1, "a first query goes back to the sender");
    assert!(net.devs[1].reconciling.contains_key(&*ORG));
    let h = deliver_inner(&mut net, 0, 1, &sync::more_body());
    assert!(matches!(h.event, Event::Ignored));
    assert!(h.replies.is_empty(), "no second round while one runs");
}

/// req: REQ-INV-004
#[test]
fn notices_are_only_taken_in_the_org_group() {
    let mut net = Net::org(2);
    let from = hex(&net.devs[0]);
    let notices = sync::notices_bodies(&["00".into()]).remove(0);
    let sub = format!("{}/finance", *ORG);
    let h = net.devs[1]
        .handle_plain(ORG.clone(), sub, from, &notices)
        .unwrap();
    assert_eq!(reason(&h), "notices belong to the org group");
}

/// req: REQ-SYNC-005
#[test]
fn a_round_that_is_cut_at_the_batch_limit_asks_the_peer_to_continue() {
    let mut net = Net::org(2);
    for i in 0..(SYNC_BATCH_CHANGES + 20) {
        net.devs[0]
            .create(ObjectType::new("note"), i.to_le_bytes().to_vec())
            .unwrap();
    }
    // The device with the data starts: its first batch is cut, so it sends `More`.
    let frame = net.devs[0].sync_request_frame(&ORG).unwrap();
    let events = net.send(0, vec![frame]);
    assert!(
        events.iter().any(|(i, e)| *i == 0
            && matches!(e, Event::SyncCompared { sending, .. } if *sending == SYNC_BATCH_CHANGES)),
        "{events:?}"
    );
    assert_eq!(
        net.ids(1),
        net.ids(0),
        "the follow-up rounds deliver the rest"
    );
}

/// req: REQ-SYNC-001
#[test]
fn an_offer_counts_undecodable_and_foreign_scope_changes_as_rejected() {
    let mut net = Net::org(2);
    let foreign = Change::sign(
        UnsignedChange {
            scope: Scope::parse(&other_org()).unwrap(),
            object_id: ObjectId::random(),
            object_type: ObjectType::new("note"),
            parents: vec![],
            timestamp_ms: 1,
            payload: b"x".to_vec(),
        },
        net.devs[0].signer(),
    );
    let good = net.devs[0]
        .create(ObjectType::new("note"), b"ok".to_vec())
        .unwrap();
    let encoded = [
        vec![0xff; 10],
        kith_store::codec::encode_change(&foreign),
        kith_store::codec::encode_change(&good),
    ];
    let mut inner = vec![3u8];
    inner.extend_from_slice(&0u32.to_be_bytes()); // nothing wanted
    inner.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    for e in &encoded {
        inner.extend_from_slice(&(e.len() as u32).to_be_bytes());
        inner.extend_from_slice(e);
    }
    let h = deliver_inner(&mut net, 0, 1, &inner);
    assert!(
        matches!(
            h.event,
            Event::SyncReceived {
                stored: 1,
                known: 0,
                rejected: 2,
                requested: 0,
                ..
            }
        ),
        "{h:?}"
    );
    assert!(h.replies.is_empty());
    assert!(net.devs[1].store().contains(&good.change_id).unwrap());
    assert!(!net.devs[1].store().contains(&foreign.change_id).unwrap());
}
