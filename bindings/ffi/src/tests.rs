use super::*;

/// req: REQ-PLAT-002
#[test]
fn restored_key_keeps_device_identity() {
    let a = KithClient::new();
    let b = KithClient::with_secret_key(a.secret_key()).unwrap();
    assert_eq!(a.device_id(), b.device_id());
    let c = b.create("note".into(), b"x".to_vec()).unwrap();
    assert_eq!(c.author, a.device_id());
    assert_ne!(KithClient::new().device_id(), a.device_id());
}

/// req: REQ-PLAT-002
/// req: REQ-STORE-001
#[test]
fn open_persists_data_and_identity() {
    let dir = std::env::temp_dir().join(format!(
        "kith-ffi-{}",
        generate_secret_key()[0..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kith.db").to_string_lossy().into_owned();
    let key = generate_secret_key();

    let first = KithClient::open(path.clone(), key.clone()).unwrap();
    let created = first.create("note".into(), b"v1".to_vec()).unwrap();
    first
        .edit(created.object_id.clone(), b"v2".to_vec())
        .unwrap();
    let device = first.device_id();
    drop(first);

    let second = KithClient::open(path, key).unwrap();
    assert_eq!(second.device_id(), device);
    assert_eq!(second.history(created.object_id).unwrap().len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}

/// req: REQ-DATA-006
#[test]
fn backups_restore_into_a_new_database() {
    let a = KithClient::new();
    let note = a.create("note".into(), b"keep me".to_vec()).unwrap();
    let backup = a.export_backup("pw".into()).unwrap();
    let dir = std::env::temp_dir().join(format!("kith-ffi-restore-{}", note.change_id));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kith.db").to_string_lossy().into_owned();
    assert!(KithClient::restore(path.clone(), backup.clone(), "nope".into()).is_err());
    let b = KithClient::restore(path, backup, "pw".into()).unwrap();
    assert_eq!(b.device_id(), a.device_id());
    assert_eq!(b.history(note.object_id).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn open_rejects_bad_key_and_bad_path() {
    assert!(KithClient::open("/nonexistent-dir/x.db".into(), generate_secret_key()).is_err());
    assert!(KithClient::open(":memory:".into(), vec![1; 5]).is_err());
}

/// Deliver a frame one session sent to the other, as the relay would.
fn relay_to(from: &KithClient, to: &RelaySession, frame: &[u8]) -> SessionOutput {
    use kith_protocol::Frame;
    let deliver = match kith_protocol::decode(frame).unwrap() {
        Frame::InviteClaim { org, body, .. } => Frame::ClaimDeliver {
            org,
            from: from.device_id(),
            body,
        },
        Frame::SyncRequest { org, body }
        | Frame::Broadcast { org, body }
        | Frame::Direct { org, body, .. } => Frame::Deliver {
            org,
            from: from.device_id(),
            body,
        },
        _ => panic!("frame with a body expected"),
    };
    to.receive(kith_protocol::encode(&deliver).unwrap())
        .unwrap()
}

/// `a` invites `b`, `b` claims, `a` accepts. Returns the replies `b` sent after
/// joining (its announcement with the certificate, then its catch-up request).
fn join(
    a: &Arc<KithClient>,
    sa: &RelaySession,
    b: &Arc<KithClient>,
    sb: &RelaySession,
) -> Vec<Vec<u8>> {
    let org = sa.org.clone();
    let link = a
        .create_invite(org.clone(), "ws://relay/v1/ws".into(), 60)
        .unwrap();
    let info = parse_invite(link.clone()).unwrap();
    assert_eq!(
        (info.org.as_str(), info.relay.as_str()),
        (org.as_str(), "ws://relay/v1/ws")
    );
    let claim = sb.claim(link).unwrap();
    let out = relay_to(b, sa, &claim);
    let Some(RelayEvent::InviteClaimed { from, code, .. }) = out.event else {
        panic!("claim expected")
    };
    let answer = relay_to(a, sb, &out.replies[0]);
    let Some(RelayEvent::ClaimCode { code: shown, .. }) = answer.event else {
        panic!("the admin's answer expected")
    };
    assert_eq!(code, shown, "both screens show the same code");
    let frames = sa.accept_claim(from).unwrap();
    assert_eq!(frames.len(), 3, "b named in the policy + commit + welcome");
    // The commit reaches b before it is a member; the Welcome then adds it.
    // (The policy change, in the old epoch, reaches b with the catch-up.)
    let _ = relay_to(a, sb, &frames[1]);
    let out = relay_to(a, sb, &frames[2]);
    assert!(matches!(out.event, Some(RelayEvent::Joined { .. })));
    assert!(b.is_member(org.clone()));
    assert_eq!(a.group_members(org).unwrap().len(), 2);
    assert_eq!(out.replies.len(), 2);
    assert!(matches!(
        kith_protocol::decode(&out.replies[0]).unwrap(),
        kith_protocol::Frame::Announce { orgs } if !orgs[0].proof.is_empty()
    ));
    out.replies[1..].to_vec()
}

/// Relay `frames` sent by `first` back and forth until nobody replies.
fn bounce(
    first: (&KithClient, &RelaySession),
    second: (&KithClient, &RelaySession),
    frames: Vec<Vec<u8>>,
) {
    let mut queue: Vec<(bool, Vec<u8>)> = frames.into_iter().map(|f| (true, f)).collect();
    while let Some((from_first, f)) = queue.pop() {
        let (from, to) = if from_first {
            (first, second)
        } else {
            (second, first)
        };
        let out = relay_to(from.0, to.1, &f);
        queue.extend(out.replies.into_iter().map(|r| (!from_first, r)));
    }
}

/// `a` created an org; sessions for it on `a` and `b` (not a member yet).
fn pair() -> (
    Arc<KithClient>,
    Arc<RelaySession>,
    Arc<KithClient>,
    Arc<RelaySession>,
) {
    let a = Arc::new(KithClient::new());
    let b = Arc::new(KithClient::new());
    let org = a.create_org().unwrap();
    assert!(a.is_admin(org.clone()));
    let sa = a.clone().relay_session(org.clone());
    let sb = b.clone().relay_session(org);
    (a, sa, b, sb)
}

/// req: REQ-SYNC-004
/// req: REQ-ENC-001
#[test]
fn sessions_exchange_encrypted_changes_through_frames() {
    let (a, sa, b, sb) = pair();

    // Handshake: hello -> (relay) challenge -> auth + announce.
    let hello = kith_protocol::decode(&sa.hello().unwrap()).unwrap();
    assert!(matches!(hello, kith_protocol::Frame::Hello { .. }));
    let challenge =
        kith_protocol::encode(&kith_protocol::Frame::Challenge { nonce: "ab".into() }).unwrap();
    let out = sa.receive(challenge).unwrap();
    assert!(out.event.is_none());
    let frames: Vec<_> = out
        .replies
        .iter()
        .map(|f| kith_protocol::decode(f).unwrap())
        .collect();
    assert!(matches!(frames[0], kith_protocol::Frame::Auth { .. }));
    assert!(matches!(frames[1], kith_protocol::Frame::Announce { .. }));

    // Not a member yet: nothing can be sent.
    let early = b.create("note".into(), b"early".to_vec()).unwrap();
    assert!(sb.broadcast(early.change_id).is_err());
    join(&a, &sa, &b, &sb);

    // A change made on a reaches b.
    let created = a.create("note".into(), b"v1".to_vec()).unwrap();
    let broadcast = sa.broadcast(created.change_id.clone()).unwrap();
    let out = relay_to(&a, &sb, &broadcast);
    match out.event {
        Some(RelayEvent::Received {
            object_id,
            change_id,
            is_new,
            from,
            ..
        }) => {
            assert_eq!(object_id, created.object_id);
            assert_eq!(change_id, created.change_id);
            assert_eq!(from, a.device_id());
            assert!(is_new);
        }
        _ => panic!("expected a received event"),
    }
    assert_eq!(b.history(created.object_id).unwrap().len(), 1);
    assert!(sa.broadcast("00".repeat(32)).is_err(), "unknown change");
    // Key rotation and removal produce frames.
    let rotate = relay_to(&b, &sa, &sb.rotate_key().unwrap());
    assert!(matches!(
        rotate.event,
        Some(RelayEvent::GroupChanged { removed: false, .. })
    ));
    // Roles: b first catches up (it gets the policy), then a demotes and removes it.
    bounce((&b, &sb), (&a, &sa), sb.catch_up().unwrap());
    let demote = relay_to(
        &a,
        &sb,
        &sa.set_role(b.device_id(), "viewer".into()).unwrap(),
    );
    assert!(matches!(demote.event, Some(RelayEvent::Received { .. })));
    assert_eq!(
        sb.role_of(b.device_id()).unwrap().as_deref(),
        Some("viewer")
    );
    assert!(b.create("note".into(), b"no".to_vec()).is_err());
    assert!(sa.set_role(b.device_id(), "boss".into()).is_err());
    assert!(
        sb.set_write_rule("note".into(), "viewer".into()).is_err(),
        "not an admin"
    );
    let frames = sa.remove_member(b.device_id()).unwrap();
    let removal = relay_to(&a, &sb, &frames[0]);
    assert!(matches!(
        removal.event,
        Some(RelayEvent::GroupChanged { removed: true, .. })
    ));
    assert_eq!(sa.role_of(b.device_id()).unwrap(), None);
}

/// req: REQ-SYNC-003
#[test]
fn joining_downloads_the_history_into_an_empty_client() {
    let (a, sa, b, sb) = pair();
    let created = a.create("note".into(), b"v1".to_vec()).unwrap();
    a.edit(created.object_id.clone(), b"v2".to_vec()).unwrap();

    // Joining asks for the history on its own: a answers the reconciliation,
    // b asks for the 2 changes it lacks, a sends them.
    let replies = join(&a, &sa, &b, &sb);
    assert_eq!(replies.len(), 1);
    let served = relay_to(&b, &sa, &replies[0]);
    assert!(matches!(served.event, Some(RelayEvent::SyncServed { .. })));
    let compared = relay_to(&a, &sb, &served.replies[0]);
    assert!(
        matches!(
            compared.event,
            Some(RelayEvent::SyncCompared { wanting: 4, .. })
        ),
        "2 notes + the policy genesis + b named in the policy"
    );
    let asked = relay_to(&b, &sa, &compared.replies[0]);
    assert!(matches!(
        asked.event,
        Some(RelayEvent::SyncReceived { requested: 4, .. })
    ));
    let received = relay_to(&a, &sb, &asked.replies[0]);
    assert!(matches!(
        received.event,
        Some(RelayEvent::SyncReceived { stored: 4, .. })
    ));
    assert_eq!(b.history(created.object_id.clone()).unwrap().len(), 2);
    // And catch_up works the same way later: nothing to do now.
    let served = relay_to(&b, &sa, &sb.catch_up().unwrap()[0]);
    let compared = relay_to(&a, &sb, &served.replies[0]);
    assert!(matches!(
        compared.event,
        Some(RelayEvent::SyncCompared {
            sending: 0,
            wanting: 0,
            ..
        })
    ));
}

/// req: REQ-SYNC-004
/// req: REQ-ENC-001
#[test]
fn tampered_and_garbage_frames_do_not_store_anything() {
    let (a, sa, b, sb) = pair();
    join(&a, &sa, &b, &sb);
    let created = a.create("note".into(), b"v1".to_vec()).unwrap();
    let broadcast = sa.broadcast(created.change_id).unwrap();
    let kith_protocol::Frame::Broadcast { org, mut body } =
        kith_protocol::decode(&broadcast).unwrap()
    else {
        panic!()
    };
    *body.last_mut().unwrap() ^= 1;
    let tampered = kith_protocol::encode(&kith_protocol::Frame::Deliver {
        org,
        from: a.device_id(),
        body,
    })
    .unwrap();
    let out = sb.receive(tampered).unwrap();
    assert!(matches!(out.event, Some(RelayEvent::Rejected { .. })));
    assert!(sb.receive(b"not a frame".to_vec()).is_err());
    assert!(b.history(created.object_id).unwrap().is_empty());
}

/// req: REQ-FILE-002
#[test]
fn files_through_sessions() {
    let (a, sa, b, sb) = pair();
    let catch_up = join(&a, &sa, &b, &sb);
    bounce((&b, &sb), (&a, &sa), catch_up);
    let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    let f = a
        .add_file(
            "x.bin".into(),
            "application/octet-stream".into(),
            data.clone(),
        )
        .unwrap();
    let _ = relay_to(&a, &sb, &sa.broadcast(f.change_id).unwrap());
    assert_eq!(b.file_info(f.object_id.clone()).unwrap().missing, 2);
    assert!(b.read_file(f.object_id.clone()).is_err());
    bounce(
        (&b, &sb),
        (&a, &sa),
        sb.fetch_file(f.object_id.clone()).unwrap(),
    );
    assert_eq!(b.read_file(f.object_id).unwrap(), data);
}

/// req: REQ-PERM-003
#[test]
fn subgroups_through_sessions() {
    let (a, sa, b, sb) = pair();
    // b's catch-up after joining brings it the policy.
    let catch_up = join(&a, &sa, &b, &sb);
    bounce((&b, &sb), (&a, &sa), catch_up);
    let frames = sa
        .create_subgroup("finance".into(), vec![b.device_id()])
        .unwrap();
    bounce((&a, &sa), (&b, &sb), frames);
    assert_eq!(sb.my_subgroups(), vec!["finance".to_string()]);
    assert_eq!(sa.subgroup_members("finance".into()).unwrap().len(), 2);
    let scope = format!("{}/finance", sa.org);
    let c = a
        .create_in(scope.clone(), "ledger".into(), b"x".to_vec())
        .unwrap();
    let out = relay_to(&a, &sb, &sa.broadcast(c.change_id.clone()).unwrap());
    assert!(matches!(out.event, Some(RelayEvent::Received { .. })));
    assert!(a.create_in("bad scope".into(), "x".into(), vec![]).is_err());
}

/// req: REQ-ENC-001
#[test]
fn group_membership_survives_reopen() {
    let dir = std::env::temp_dir().join(format!(
        "kith-ffi-mls-{}",
        generate_secret_key()[0..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kith.db").to_string_lossy().into_owned();
    let key = generate_secret_key();
    let org = {
        let c = KithClient::open(path.clone(), key.clone()).unwrap();
        c.create_org().unwrap()
    };
    let c = KithClient::open(path, key).unwrap();
    assert!(c.is_member(org.clone()));
    assert!(c.is_admin(org));
    let _ = std::fs::remove_dir_all(dir);
}

/// req: REQ-DATA-004
#[test]
fn documents_merge_across_sessions() {
    let (a, sa, b, sb) = pair();
    join(&a, &sa, &b, &sb);
    let doc = a
        .create_document("todo".into(), r#"{"title":"x"}"#.into())
        .unwrap();
    let _ = relay_to(&a, &sb, &sa.broadcast(doc.change_id).unwrap());
    let ea = a
        .update_document(doc.object_id.clone(), r#"{"owner":"ann"}"#.into())
        .unwrap()
        .unwrap();
    let eb = b
        .update_document(doc.object_id.clone(), r#"{"done":true}"#.into())
        .unwrap()
        .unwrap();
    let _ = relay_to(&a, &sb, &sa.broadcast(ea.change_id).unwrap());
    let _ = relay_to(&b, &sa, &sb.broadcast(eb.change_id).unwrap());
    let want: serde_json::Value =
        serde_json::from_str(r#"{"title":"x","owner":"ann","done":true}"#).unwrap();
    for c in [&a, &b] {
        let got: serde_json::Value =
            serde_json::from_str(&c.document_json(doc.object_id.clone()).unwrap()).unwrap();
        assert_eq!(got, want);
    }
    assert!(a.create_document("todo".into(), "[]".into()).is_err());
}

/// req: REQ-PLAT-002
#[test]
fn rejects_wrong_length_secret_key() {
    assert!(KithClient::with_secret_key(vec![0; 31]).is_err());
    assert!(KithClient::with_secret_key(vec![0; 33]).is_err());
}
