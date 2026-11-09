use super::*;
use futures_util::{SinkExt, StreamExt};
use kith_client::{auth_frame, hello_frame};
use kith_core::Signer;
use kith_core::membership::MembershipCert;
use kith_crypto::DeviceKey;
use kith_protocol::Membership;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn start(auth_timeout: Duration) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app(new_state(auth_timeout)))
            .await
            .unwrap();
    });
    url
}

async fn send_frame(ws: &mut Ws, f: &Frame) {
    ws.send(tungstenite::Message::Binary(encode(f).unwrap().into()))
        .await
        .unwrap();
}

/// Next frame, or `None` if the connection was closed.
async fn next_frame(ws: &mut Ws) -> Option<Frame> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for the relay");
        match msg {
            Some(Ok(tungstenite::Message::Binary(b))) => return Some(decode(&b).unwrap()),
            Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

async fn connect(url: &str) -> Ws {
    connect_async(url).await.unwrap().0
}

/// Full handshake; returns the authenticated socket.
async fn login(url: &str, key: &DeviceKey) -> Ws {
    let mut ws = connect(url).await;
    send_frame(&mut ws, &hello_frame(key)).await;
    let Some(Frame::Challenge { nonce }) = next_frame(&mut ws).await else {
        panic!("expected challenge");
    };
    send_frame(&mut ws, &auth_frame(key, &nonce)).await;
    ws
}

fn org_id(root: &DeviceKey) -> String {
    root.device_id().to_hex()
}

/// A membership proof for `key` in `root`'s org, issued by the root.
fn proof(root: &DeviceKey, key: &DeviceKey, admin: bool) -> String {
    CertChain(vec![MembershipCert::issue(
        root,
        root.device_id(),
        key.device_id(),
        admin,
        1,
    )])
    .to_hex()
}

async fn announce(ws: &mut Ws, org: &str, proof: String) {
    send_frame(
        ws,
        &Frame::Announce {
            orgs: vec![Membership {
                org: org.into(),
                proof,
                always_on: false,
                revoked: vec![],
            }],
        },
    )
    .await;
}

/// Announce `key` as a member of `root`'s org.
async fn join(ws: &mut Ws, root: &DeviceKey, key: &DeviceKey) {
    announce(ws, &org_id(root), proof(root, key, false)).await;
    // Our own join is announced to us as presence.
    assert!(matches!(next_frame(ws).await, Some(Frame::Presence { .. })));
}

/// Skip presence updates until the next error, and check its code.
async fn expect_error_after_presence(ws: &mut Ws, code: &str) {
    loop {
        match next_frame(ws).await {
            Some(Frame::Presence { .. }) => continue,
            other => return expect_error(other, code),
        }
    }
}

fn member_cert_hex(cert: &MembershipCert) -> String {
    CertChain(vec![cert.clone()]).to_hex()
}

fn expect_error(f: Option<Frame>, code: &str) {
    match f {
        Some(Frame::Error { code: c, .. }) => assert_eq!(c, code),
        other => panic!("expected error {code}, got {other:?}"),
    }
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn authenticated_devices_can_exchange_messages() {
    let url = start(Duration::from_secs(10)).await;
    let (root, ka, kb) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    // a sees b come online.
    assert!(matches!(
        next_frame(&mut a).await,
        Some(Frame::Presence { .. })
    ));

    send_frame(
        &mut a,
        &Frame::Broadcast {
            org: org_id(&root),
            body: b"hi".to_vec(),
        },
    )
    .await;
    assert!(
        matches!(next_frame(&mut a).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
    );
    match next_frame(&mut b).await {
        Some(Frame::Deliver { from, body, .. }) => {
            assert_eq!(from, ka.device_id().to_hex());
            assert_eq!(body, b"hi");
        }
        other => panic!("expected deliver, got {other:?}"),
    }
}

/// req: REQ-RELAY-008
#[tokio::test]
async fn only_allowed_orgs_are_served() {
    let state = new_state(Duration::from_secs(10));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let served = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
    let (ok_root, other_root) = (DeviceKey::generate(), DeviceKey::generate());
    let (ka, kb) = (DeviceKey::generate(), DeviceKey::generate());
    // Written in upper case: the list is case-insensitive.
    let list = format!("  {}, bogus\n", org_id(&ok_root).to_ascii_uppercase());
    set_allowed_orgs(&state, parse_allowed_orgs(&list));

    let mut a = login(&url, &ka).await;
    join(&mut a, &ok_root, &ka).await;

    // A valid proof for another org is still refused, and the device cannot route there.
    let mut b = login(&url, &kb).await;
    announce(&mut b, &org_id(&other_root), proof(&other_root, &kb, true)).await;
    expect_error(next_frame(&mut b).await, "org-not-allowed");
    send_frame(
        &mut b,
        &Frame::Broadcast {
            org: org_id(&other_root),
            body: vec![1],
        },
    )
    .await;
    expect_error(next_frame(&mut b).await, "not-a-member");

    // Lifting the restriction serves the org again.
    set_allowed_orgs(&state, parse_allowed_orgs(""));
    join(&mut b, &other_root, &kb).await;
}

/// req: REQ-RELAY-009
#[tokio::test]
async fn open_mode_ignores_the_list_but_keeps_revocation_storage() {
    use crate::state::{BoxFuture, OpenOrgs, RevocationRecord, StateStore, refresh_allowlist};
    /// A configured store with an empty list (approves nobody) that keeps revocations.
    struct Closed;
    impl StateStore for Closed {
        fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
            Box::pin(async { Ok(Some(HashSet::new())) })
        }
        fn keeps_revocations(&self) -> bool {
            true
        }
        fn save_revocation<'a>(
            &'a self,
            _rec: &'a RevocationRecord,
        ) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async { Ok(()) })
        }
    }
    let state = new_state(Duration::from_secs(10));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let served = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
    let (root, key) = (DeviceKey::generate(), DeviceKey::generate());

    // Closed store: nobody is approved.
    refresh_allowlist(&state, &Closed).await.unwrap();
    let mut a = login(&url, &key).await;
    announce(&mut a, &org_id(&root), proof(&root, &key, true)).await;
    expect_error(next_frame(&mut a).await, "org-not-allowed");

    // Open mode over the same store: the list is not consulted, persistence is kept.
    let open = OpenOrgs(Arc::new(Closed));
    assert!(open.keeps_revocations());
    assert!(!open.refreshes());
    refresh_allowlist(&state, &open).await.unwrap();
    join(&mut a, &root, &key).await;
}

/// req: REQ-RELAY-008
#[tokio::test]
async fn removing_an_org_from_the_list_evicts_its_devices() {
    let state = new_state(Duration::from_secs(10));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    let served = state.clone();
    tokio::spawn(async move { axum::serve(listener, app(served)).await.unwrap() });
    let (root, other) = (DeviceKey::generate(), DeviceKey::generate());
    let key = DeviceKey::generate();
    let both = format!("{} {}", org_id(&root), org_id(&other));
    set_allowed_orgs(&state, parse_allowed_orgs(&both));
    let mut a = login(&url, &key).await;
    join(&mut a, &root, &key).await;
    join(&mut a, &other, &key).await;

    set_allowed_orgs(&state, parse_allowed_orgs(&org_id(&other)));
    expect_error(next_frame(&mut a).await, "org-not-allowed");
    send_frame(
        &mut a,
        &Frame::Broadcast {
            org: org_id(&root),
            body: vec![1],
        },
    )
    .await;
    expect_error(next_frame(&mut a).await, "not-a-member");
    // The other org keeps working.
    send_frame(
        &mut a,
        &Frame::Broadcast {
            org: org_id(&other),
            body: vec![1],
        },
    )
    .await;
}

#[test]
fn allowed_org_lists_parse() {
    assert_eq!(parse_allowed_orgs(""), None);
    assert_eq!(parse_allowed_orgs(" , \n"), None);
    let set = parse_allowed_orgs("AB,cd ef\n12").unwrap();
    assert_eq!(set.len(), 4);
    assert!(set.contains("ab") && set.contains("12"));
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn frames_before_authentication_are_refused() {
    let url = start(Duration::from_secs(10)).await;
    let key = DeviceKey::generate();
    let mut ws = connect(&url).await;
    let broadcast = Frame::Broadcast {
        org: "org".into(),
        body: vec![1],
    };
    send_frame(&mut ws, &broadcast).await;
    expect_error(next_frame(&mut ws).await, "unauthenticated");

    send_frame(&mut ws, &hello_frame(&key)).await;
    assert!(matches!(
        next_frame(&mut ws).await,
        Some(Frame::Challenge { .. })
    ));
    send_frame(&mut ws, &broadcast).await; // challenged but not yet authenticated
    expect_error(next_frame(&mut ws).await, "unauthenticated");
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn wrong_key_or_garbage_signature_fails() {
    let url = start(Duration::from_secs(10)).await;
    let (claimed, other) = (DeviceKey::generate(), DeviceKey::generate());

    // Signs the right message with a different key.
    let mut ws = connect(&url).await;
    send_frame(&mut ws, &hello_frame(&claimed)).await;
    let Some(Frame::Challenge { nonce }) = next_frame(&mut ws).await else {
        panic!()
    };
    send_frame(&mut ws, &auth_frame(&other, &nonce)).await;
    expect_error(next_frame(&mut ws).await, "auth-failed");
    assert!(next_frame(&mut ws).await.is_none(), "connection is closed");

    // Not even hex.
    let mut ws = connect(&url).await;
    send_frame(&mut ws, &hello_frame(&claimed)).await;
    let Some(Frame::Challenge { .. }) = next_frame(&mut ws).await else {
        panic!()
    };
    send_frame(
        &mut ws,
        &Frame::Auth {
            signature: "zz".into(),
        },
    )
    .await;
    expect_error(next_frame(&mut ws).await, "auth-failed");

    // A valid signature for an old nonce does not work on a new connection.
    let mut first = connect(&url).await;
    send_frame(&mut first, &hello_frame(&claimed)).await;
    let Some(Frame::Challenge { nonce: old }) = next_frame(&mut first).await else {
        panic!()
    };
    let mut second = connect(&url).await;
    send_frame(&mut second, &hello_frame(&claimed)).await;
    let Some(Frame::Challenge { nonce: new }) = next_frame(&mut second).await else {
        panic!()
    };
    assert_ne!(old, new);
    send_frame(&mut second, &auth_frame(&claimed, &old)).await;
    expect_error(next_frame(&mut second).await, "auth-failed");
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn device_id_must_be_a_public_key() {
    let url = start(Duration::from_secs(10)).await;
    let mut ws = connect(&url).await;
    send_frame(
        &mut ws,
        &Frame::Hello {
            version: PROTOCOL_VERSION,
            device: "alice".into(),
        },
    )
    .await;
    expect_error(next_frame(&mut ws).await, "bad-device");
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn protocol_versions_outside_the_supported_range_are_refused() {
    let url = start(Duration::from_secs(10)).await;
    for version in [MIN_PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
        let mut ws = connect(&url).await;
        let key = DeviceKey::generate();
        send_frame(
            &mut ws,
            &Frame::Hello {
                version,
                device: key.device_id().to_hex(),
            },
        )
        .await;
        expect_error(next_frame(&mut ws).await, "version");
    }
    // The oldest supported version still gets its challenge.
    let mut ws = connect(&url).await;
    let key = DeviceKey::generate();
    send_frame(
        &mut ws,
        &Frame::Hello {
            version: MIN_PROTOCOL_VERSION,
            device: key.device_id().to_hex(),
        },
    )
    .await;
    assert!(matches!(
        next_frame(&mut ws).await,
        Some(Frame::Challenge { .. })
    ));
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn unauthenticated_connections_time_out() {
    let url = start(Duration::from_millis(200)).await;
    let mut ws = connect(&url).await;
    expect_error(next_frame(&mut ws).await, "auth-timeout");
    assert!(next_frame(&mut ws).await.is_none());
}

/// req: REQ-RELAY-001
#[tokio::test]
async fn reconnecting_replaces_the_old_connection_without_dropping_the_new_one() {
    let url = start(Duration::from_secs(10)).await;
    let (root, ka, kb) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let mut old = login(&url, &ka).await;
    join(&mut old, &root, &ka).await;
    let mut new = login(&url, &ka).await;
    join(&mut new, &root, &ka).await;
    // The old connection is closed by the relay...
    assert!(next_frame(&mut old).await.is_none());
    // ...and its teardown did not unregister the new one.
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    send_frame(
        &mut b,
        &Frame::Broadcast {
            org: org_id(&root),
            body: b"x".to_vec(),
        },
    )
    .await;
    loop {
        match next_frame(&mut new).await {
            Some(Frame::Deliver { body, .. }) => {
                assert_eq!(body, b"x");
                break;
            }
            Some(Frame::Presence { .. }) => continue,
            other => panic!("expected deliver, got {other:?}"),
        }
    }
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn bad_proofs_are_refused_and_non_members_cannot_send() {
    let url = start(Duration::from_secs(10)).await;
    let (root, key) = (DeviceKey::generate(), DeviceKey::generate());
    let mut ws = login(&url, &key).await;
    let org = org_id(&root);
    // Garbage, a chain for another device, a self-made chain, a name as org ID.
    announce(&mut ws, &org, "zz".into()).await;
    expect_error(next_frame(&mut ws).await, "bad-proof");
    announce(&mut ws, &org, proof(&root, &DeviceKey::generate(), false)).await;
    expect_error(next_frame(&mut ws).await, "bad-proof");
    announce(&mut ws, &org, proof(&key, &key, true)).await;
    expect_error(next_frame(&mut ws).await, "bad-proof");
    announce(&mut ws, "my-org", proof(&root, &key, false)).await;
    expect_error(next_frame(&mut ws).await, "bad-org");
    for f in [
        Frame::Broadcast {
            org: org.clone(),
            body: vec![1],
        },
        Frame::SyncRequest {
            org: org.clone(),
            body: vec![1],
        },
        Frame::Direct {
            org: org.clone(),
            to: root.device_id().to_hex(),
            body: vec![1],
        },
    ] {
        send_frame(&mut ws, &f).await;
        expect_error(next_frame(&mut ws).await, "not-a-member");
    }
}

/// req: REQ-INV-004
#[tokio::test]
async fn a_signed_revocation_removes_the_device_and_keeps_it_out() {
    use kith_core::membership::Revocation;
    let url = start(Duration::from_secs(10)).await;
    let (root, admin_key, member_key, own_key) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let (org, rid) = (org_id(&root), root.device_id());
    let admin_chain = CertChain(vec![MembershipCert::issue(
        &root,
        rid,
        admin_key.device_id(),
        true,
        1,
    )]);
    let member_cert = MembershipCert::issue(&root, rid, member_key.device_id(), false, 1);
    // The member's own device is certified through the member.
    let own_chain = CertChain(vec![
        member_cert.clone(),
        MembershipCert::issue_own(&member_key, rid, own_key.device_id(), 2),
    ]);
    let mut admin = login(&url, &admin_key).await;
    join(&mut admin, &root, &admin_key).await;
    let mut member = login(&url, &member_key).await;
    join(&mut member, &root, &member_key).await;
    assert!(matches!(
        next_frame(&mut admin).await,
        Some(Frame::Presence { .. })
    ));
    let mut own = login(&url, &own_key).await;
    announce(&mut own, &org, own_chain.to_hex()).await;
    assert!(matches!(
        next_frame(&mut own).await,
        Some(Frame::Presence { .. })
    ));
    assert!(matches!(
        next_frame(&mut admin).await,
        Some(Frame::Presence { .. })
    ));
    assert!(matches!(
        next_frame(&mut member).await,
        Some(Frame::Presence { .. })
    ));

    let announce_with = |notices: Vec<String>| Frame::Announce {
        orgs: vec![Membership {
            org: org.clone(),
            proof: admin_chain.to_hex(),
            always_on: false,
            revoked: notices,
        }],
    };
    // A notice from a plain member is refused and changes nothing.
    let member_chain = CertChain(vec![member_cert.clone()]);
    let forged = Revocation::issue(&member_key, member_chain, rid, admin_key.device_id(), 3);
    send_frame(&mut admin, &announce_with(vec![forged.to_hex()])).await;
    expect_error(next_frame(&mut admin).await, "bad-revocation");
    // (The announce itself still goes through and refreshes presence.)
    while !matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 3)
    {
    }

    // The admin's notice removes the member and the device certified through it.
    let notice = Revocation::issue(
        &admin_key,
        admin_chain.clone(),
        rid,
        member_key.device_id(),
        4,
    );
    send_frame(&mut admin, &announce_with(vec![notice.to_hex()])).await;
    expect_error_after_presence(&mut member, "revoked").await;
    expect_error_after_presence(&mut own, "revoked").await;
    loop {
        match next_frame(&mut admin).await {
            Some(Frame::Presence { online, .. }) if online.len() == 1 => break,
            Some(Frame::Presence { .. }) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
    // They are out of the org: nothing they send is routed.
    send_frame(
        &mut member,
        &Frame::Broadcast {
            org: org.clone(),
            body: b"x".to_vec(),
        },
    )
    .await;
    expect_error_after_presence(&mut member, "not-a-member").await;
    // Announcing again is refused, with or without the notice being repeated.
    announce(&mut member, &org, member_cert_hex(&member_cert)).await;
    expect_error_after_presence(&mut member, "revoked").await;
    announce(&mut own, &org, own_chain.to_hex()).await;
    expect_error_after_presence(&mut own, "revoked").await;
    // A fresh device of the admin still joins.
    let mut other = login(&url, &DeviceKey::generate()).await;
    send_frame(&mut other, &announce_with(vec![])).await;
    expect_error(next_frame(&mut other).await, "bad-proof");
}

/// req: REQ-INV-004
#[tokio::test]
async fn stored_revocations_survive_a_relay_restart() {
    use crate::state::{
        BoxFuture, RevocationRecord, StateStore, load_revocations, spawn_revocation_writer,
    };
    use kith_core::membership::Revocation;
    #[derive(Default)]
    struct Mem(Mutex<Vec<RevocationRecord>>);
    impl StateStore for Mem {
        fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
            Box::pin(async { Ok(None) })
        }
        fn keeps_revocations(&self) -> bool {
            true
        }
        fn save_revocation<'a>(
            &'a self,
            rec: &'a RevocationRecord,
        ) -> BoxFuture<'a, Result<(), String>> {
            self.0.lock().unwrap().push(rec.clone());
            Box::pin(async { Ok(()) })
        }
    }
    let serve = |state: Shared| async move {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app(state)).await.unwrap() });
        url
    };
    let (root, admin_key, member_key) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let (org, rid) = (org_id(&root), root.device_id());
    let admin_chain = CertChain(vec![MembershipCert::issue(
        &root,
        rid,
        admin_key.device_id(),
        true,
        1,
    )]);
    let member_cert = MembershipCert::issue(&root, rid, member_key.device_id(), false, 1);
    let notice = Revocation::issue(
        &admin_key,
        admin_chain.clone(),
        rid,
        member_key.device_id(),
        4,
    );

    // Relay 1 accepts the notice and hands it to the store.
    let store = Arc::new(Mem::default());
    let state1 = new_state(Duration::from_secs(10));
    spawn_revocation_writer(&state1, store.clone());
    let url1 = serve(state1).await;
    let mut admin = login(&url1, &admin_key).await;
    send_frame(
        &mut admin,
        &Frame::Announce {
            orgs: vec![Membership {
                org: org.clone(),
                proof: admin_chain.to_hex(),
                always_on: false,
                revoked: vec![notice.to_hex()],
            }],
        },
    )
    .await;
    for _ in 0..50 {
        if !store.0.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let records = store.0.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].device, member_key.device_id().to_hex());

    // A new relay that loads the records refuses the device without any admin online.
    let state2 = new_state(Duration::from_secs(10));
    assert_eq!(load_revocations(&state2, &records), 1);
    // A forged record is skipped.
    let bogus = RevocationRecord {
        notice: "00".into(),
        ..records[0].clone()
    };
    assert_eq!(load_revocations(&state2, &[bogus]), 0);
    let url2 = serve(state2).await;
    let mut member = login(&url2, &member_key).await;
    announce(&mut member, &org, member_cert_hex(&member_cert)).await;
    expect_error(next_frame(&mut member).await, "revoked");
}

/// req: REQ-ID-002
#[tokio::test]
async fn a_claim_can_be_addressed_to_one_certified_member() {
    let url = start(Duration::from_secs(10)).await;
    let (root, member_key, new_key) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let org = org_id(&root);
    let mut member = login(&url, &member_key).await;
    announce(&mut member, &org, proof(&root, &member_key, false)).await;
    assert!(matches!(
        next_frame(&mut member).await,
        Some(Frame::Presence { .. })
    ));
    let mut new = login(&url, &new_key).await;
    announce(&mut new, &org, String::new()).await;
    let claim = |to: String| Frame::InviteClaim {
        org: org.clone(),
        token: "t".into(),
        body: b"claim".to_vec(),
        to: Some(to),
    };
    // No admin is online, but the claim reaches the named (non-admin) member.
    send_frame(&mut new, &claim(member_key.device_id().to_hex())).await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
    );
    assert!(
        matches!(next_frame(&mut member).await, Some(Frame::ClaimDeliver { body, .. }) if body == b"claim")
    );
    // A pending or unknown device is not a target.
    send_frame(&mut new, &claim(new_key.device_id().to_hex())).await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
    );
    send_frame(&mut new, &claim("00".repeat(32))).await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
    );
}

/// req: REQ-RELAY-004
/// req: REQ-INV-002
#[tokio::test]
async fn a_pending_device_can_only_claim_and_receive_until_it_proves_membership() {
    let url = start(Duration::from_secs(10)).await;
    let (root, admin_key, new_key) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let org = org_id(&root);
    let mut admin = login(&url, &admin_key).await;
    announce(&mut admin, &org, proof(&root, &admin_key, true)).await;
    assert!(
        matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 1)
    );

    // The new device announces without a proof: pending, no presence.
    let mut new = login(&url, &new_key).await;
    announce(&mut new, &org, String::new()).await;
    send_frame(
        &mut new,
        &Frame::Broadcast {
            org: org.clone(),
            body: vec![1],
        },
    )
    .await;
    expect_error(next_frame(&mut new).await, "not-a-member");
    // Its claim reaches the admin.
    send_frame(
        &mut new,
        &Frame::InviteClaim {
            org: org.clone(),
            token: "t".into(),
            body: b"claim".to_vec(),
            to: None,
        },
    )
    .await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
    );
    match next_frame(&mut admin).await {
        Some(Frame::ClaimDeliver { from, body, .. }) => {
            assert_eq!(from, new_key.device_id().to_hex());
            assert_eq!(body, b"claim");
        }
        other => panic!("expected the claim, got {other:?}"),
    }
    // The admin's direct (the Welcome) reaches the pending device.
    send_frame(
        &mut admin,
        &Frame::Direct {
            org: org.clone(),
            to: new_key.device_id().to_hex(),
            body: b"welcome".to_vec(),
        },
    )
    .await;
    assert!(
        matches!(next_frame(&mut admin).await, Some(Frame::Receipt { delivered }) if delivered.len() == 1)
    );
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Deliver { body, .. }) if body == b"welcome")
    );
    // With its certificate it becomes a member and shows up in presence.
    announce(&mut new, &org, proof(&root, &new_key, false)).await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Presence { online, .. }) if online.len() == 2)
    );
    assert!(
        matches!(next_frame(&mut admin).await, Some(Frame::Presence { online, .. }) if online.len() == 2)
    );
}

/// req: REQ-INV-002
#[tokio::test]
async fn claims_without_an_online_admin_are_dropped() {
    let url = start(Duration::from_secs(10)).await;
    let (root, member_key, new_key) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let org = org_id(&root);
    let mut member = login(&url, &member_key).await;
    join(&mut member, &root, &member_key).await;
    let mut new = login(&url, &new_key).await;
    announce(&mut new, &org, String::new()).await;
    send_frame(
        &mut new,
        &Frame::InviteClaim {
            org,
            token: "t".into(),
            body: vec![1],
            to: None,
        },
    )
    .await;
    assert!(
        matches!(next_frame(&mut new).await, Some(Frame::Receipt { delivered }) if delivered.is_empty())
    );
}

// ---- abuse limits (REQ-RELAY-006) ----

async fn start_with(limits: Limits) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app(new_state_with(Duration::from_secs(10), limits)),
        )
        .await
        .unwrap();
    });
    url
}

/// Frames that arrive within `wait`; `None` at the end if the relay closed.
async fn drain(ws: &mut Ws, wait: Duration) -> (Vec<Frame>, bool) {
    let mut out = vec![];
    loop {
        match tokio::time::timeout(wait, ws.next()).await {
            Err(_) => return (out, false),
            Ok(Some(Ok(tungstenite::Message::Binary(b)))) => out.push(decode(&b).unwrap()),
            Ok(Some(Ok(tungstenite::Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                return (out, true);
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

fn count(frames: &[Frame], pick: impl Fn(&Frame) -> bool) -> usize {
    frames.iter().filter(|f| pick(f)).count()
}

fn rate_limited(f: &Frame) -> bool {
    matches!(f, Frame::Error { code, .. } if code == "rate-limited")
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn frames_beyond_a_devices_burst_are_dropped() {
    let url = start_with(Limits {
        device_frames_per_sec: 1.0,
        device_burst: 10.0,
        ..Limits::default()
    })
    .await;
    let (root, ka, kb) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    for _ in 0..20 {
        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org_id(&root),
                body: vec![1],
            },
        )
        .await;
    }
    let (frames, closed) = drain(&mut a, Duration::from_millis(500)).await;
    assert!(!closed);
    let receipts = count(&frames, |f| matches!(f, Frame::Receipt { .. }));
    // 3 of the burst went to hello, auth and announce.
    // (A slow machine may refill a token or two while the frames are processed.)
    assert!((7..=9).contains(&receipts), "{receipts}: {frames:?}");
    assert!(count(&frames, rate_limited) >= 1);
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn persistent_abusers_are_disconnected() {
    let url = start_with(Limits {
        device_frames_per_sec: 1.0,
        device_burst: 5.0,
        max_refused: 10,
        ..Limits::default()
    })
    .await;
    let (root, ka) = (DeviceKey::generate(), DeviceKey::generate());
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    for _ in 0..40 {
        if a.send(tungstenite::Message::Binary(
            encode(&Frame::Broadcast {
                org: org_id(&root),
                body: vec![1],
            })
            .unwrap()
            .into(),
        ))
        .await
        .is_err()
        {
            break;
        }
    }
    let (_, closed) = drain(&mut a, Duration::from_secs(2)).await;
    assert!(closed, "the relay closes the connection");
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn an_org_limit_covers_all_its_devices() {
    let url = start_with(Limits {
        org_frames_per_sec: 0.5,
        ..Limits::default()
    })
    .await;
    let (root, ka, kb) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    for _ in 0..5 {
        send_frame(
            &mut a,
            &Frame::Broadcast {
                org: org_id(&root),
                body: vec![1],
            },
        )
        .await;
        send_frame(
            &mut b,
            &Frame::Broadcast {
                org: org_id(&root),
                body: vec![2],
            },
        )
        .await;
    }
    let (fa, _) = drain(&mut a, Duration::from_millis(500)).await;
    let (fb, _) = drain(&mut b, Duration::from_millis(500)).await;
    let receipts = count(&fa, |f| matches!(f, Frame::Receipt { .. }))
        + count(&fb, |f| matches!(f, Frame::Receipt { .. }));
    assert!(
        (1..=2).contains(&receipts),
        "a burst of 2 x 0.5 frames per second, shared: {receipts}"
    );
    assert!(count(&fa, rate_limited) + count(&fb, rate_limited) >= 8);
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn connections_beyond_the_maximum_are_refused() {
    let url = start_with(Limits {
        max_connections: 1,
        ..Limits::default()
    })
    .await;
    let first = connect(&url).await;
    assert!(connect_async(&url).await.is_err(), "HTTP 503");
    drop(first);
    // The slot frees up once the first connection is gone.
    for _ in 0..50 {
        if connect_async(&url).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the slot was never freed");
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn oversized_messages_close_the_connection() {
    let url = start_with(Limits {
        max_message_bytes: 1000,
        ..Limits::default()
    })
    .await;
    let mut ws = connect(&url).await;
    let _ = ws
        .send(tungstenite::Message::Binary(vec![b'x'; 5000].into()))
        .await;
    let (_, closed) = drain(&mut ws, Duration::from_secs(2)).await;
    assert!(closed);
}

// ---- revocation rules (ADR 0018) ----

fn ann(org: &str, proof: String, revoked: Vec<String>) -> Frame {
    Frame::Announce {
        orgs: vec![Membership {
            org: org.into(),
            proof,
            always_on: false,
            revoked,
        }],
    }
}

/// req: REQ-INV-004
#[tokio::test]
async fn only_the_root_removes_admins_and_revoked_admins_revoke_nobody() {
    let url = start(Duration::from_secs(10)).await;
    let root = DeviceKey::generate();
    let rid = root.device_id();
    let org = org_id(&root);
    let (ka, kb, km) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let chain_a = CertChain(vec![MembershipCert::issue(
        &root,
        rid,
        ka.device_id(),
        true,
        1,
    )]);
    let chain_b = CertChain(vec![MembershipCert::issue(
        &root,
        rid,
        kb.device_id(),
        true,
        1,
    )]);
    let mut b = login(&url, &kb).await;
    send_frame(&mut b, &ann(&org, chain_b.to_hex(), vec![])).await;
    assert!(matches!(
        next_frame(&mut b).await,
        Some(Frame::Presence { .. })
    ));
    // An admin's notice against another admin does not remove it.
    let mut a = login(&url, &ka).await;
    let a_on_b = Revocation::issue(&ka, chain_a.clone(), rid, kb.device_id(), 2);
    send_frame(&mut a, &ann(&org, chain_a.to_hex(), vec![a_on_b.to_hex()])).await;
    let mut b2 = login(&url, &kb).await;
    send_frame(&mut b2, &ann(&org, chain_b.to_hex(), vec![])).await;
    assert!(matches!(
        next_frame(&mut b2).await,
        Some(Frame::Presence { .. })
    ));
    // The root removes A.
    let root_on_a = Revocation::issue_by_root(&root, ka.device_id(), 3);
    send_frame(
        &mut b2,
        &ann(&org, chain_b.to_hex(), vec![root_on_a.to_hex()]),
    )
    .await;
    // Applied once B hears that A left (announces of different connections
    // are not ordered otherwise).
    assert!(matches!(
        next_frame(&mut b2).await,
        Some(Frame::Presence { .. })
    ));
    let mut a2 = login(&url, &ka).await;
    send_frame(&mut a2, &ann(&org, chain_a.to_hex(), vec![])).await;
    expect_error(next_frame(&mut a2).await, "revoked");
    // A's notices no longer count, even sent by someone else's announce.
    let mut m = login(&url, &km).await;
    join(&mut m, &root, &km).await;
    let a_on_m = Revocation::issue(&ka, chain_a, rid, km.device_id(), 4);
    send_frame(&mut b2, &ann(&org, chain_b.to_hex(), vec![a_on_m.to_hex()])).await;
    expect_error_after_presence(&mut b2, "bad-revocation").await;
    // A revoked device does not come back as a newcomer either.
    let mut a3 = login(&url, &ka).await;
    send_frame(&mut a3, &ann(&org, String::new(), vec![])).await;
    expect_error(next_frame(&mut a3).await, "revoked");
}

/// req: REQ-INV-004
#[tokio::test]
async fn only_admins_send_revocation_notices() {
    let url = start(Duration::from_secs(10)).await;
    let root = DeviceKey::generate();
    let org = org_id(&root);
    let (km, kx) = (DeviceKey::generate(), DeviceKey::generate());
    let mut m = login(&url, &km).await;
    join(&mut m, &root, &km).await;
    // A member hands on a valid root notice: refused, nothing changes.
    let notice = Revocation::issue_by_root(&root, kx.device_id(), 1);
    send_frame(
        &mut m,
        &ann(&org, proof(&root, &km, false), vec![notice.to_hex()]),
    )
    .await;
    expect_error(next_frame(&mut m).await, "bad-revocation");
    let mut x = login(&url, &kx).await;
    join(&mut x, &root, &kx).await;
}

/// req: REQ-RELAY-004
#[tokio::test]
async fn claims_arrive_as_claims_and_org_ids_have_one_spelling() {
    let url = start(Duration::from_secs(10)).await;
    let root = DeviceKey::generate();
    let (km, kx) = (DeviceKey::generate(), DeviceKey::generate());
    let mut m = login(&url, &km).await;
    join(&mut m, &root, &km).await;
    let mut x = login(&url, &kx).await;
    // Upper case is the same org.
    announce(&mut x, &org_id(&root).to_uppercase(), String::new()).await;
    send_frame(
        &mut x,
        &Frame::InviteClaim {
            org: org_id(&root).to_uppercase(),
            token: String::new(),
            body: b"anything".to_vec(),
            to: Some(km.device_id().to_hex()),
        },
    )
    .await;
    match next_frame(&mut m).await {
        Some(Frame::ClaimDeliver { org, body, .. }) => {
            assert_eq!(body, b"anything");
            assert_eq!(org, org_id(&root));
        }
        other => panic!("{other:?}"),
    }
}

/// req: REQ-INV-004
#[test]
fn stored_notices_of_a_removed_admin_count_only_from_before_its_removal() {
    let root = DeviceKey::generate();
    let rid = root.device_id();
    let org = org_id(&root);
    let (ka, m_old, m_new) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let chain_a = CertChain(vec![MembershipCert::issue(
        &root,
        rid,
        ka.device_id(),
        true,
        1,
    )]);
    let rec = |r: &Revocation| state::RevocationRecord {
        org: org.to_uppercase(),
        device: r.device.to_hex(),
        notice: r.to_hex(),
    };
    let before = Revocation::issue(&ka, chain_a.clone(), rid, m_old.device_id(), 5);
    let after = Revocation::issue(&ka, chain_a, rid, m_new.device_id(), 20);
    let removal = Revocation::issue_by_root(&root, ka.device_id(), 10);
    // Stored order does not matter: the root's notice is applied first.
    let shared = new_state(Duration::from_secs(10));
    state::load_revocations(&shared, &[rec(&before), rec(&after), rec(&removal)]);
    let r = shared.lock().unwrap();
    let set = r.revoked.get(&org).expect("canonical org");
    assert!(set.contains_key(&m_old.device_id().to_hex()));
    assert!(!set.contains_key(&m_new.device_id().to_hex()));
    assert!(set[&ka.device_id().to_hex()].by_root);
}

// ---- resource limits (REQ-RELAY-006, ADR 0019) ----

/// A relay on `state`, with connection info (as the binary runs it).
async fn start_state(state: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    url
}

fn claim(org: &str) -> Frame {
    Frame::InviteClaim {
        org: org.into(),
        token: "t".into(),
        body: b"claim".to_vec(),
        to: None,
    }
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn pending_devices_do_not_use_up_the_orgs_budget() {
    let url = start_with(Limits {
        org_frames_per_sec: 2.0,
        pending_frames_per_sec: 0.5,
        ..Limits::default()
    })
    .await;
    let (root, ka, kb, kp) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let org = org_id(&root);
    let mut a = login(&url, &ka).await;
    announce(&mut a, &org, proof(&root, &ka, true)).await;
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    let mut p = login(&url, &kp).await;
    announce(&mut p, &org, String::new()).await;
    for _ in 0..10 {
        send_frame(&mut p, &claim(&org)).await;
    }
    let (frames, _) = drain(&mut p, Duration::from_millis(300)).await;
    assert_eq!(
        count(&frames, |f| matches!(f, Frame::Receipt { .. })),
        1,
        "a burst of 2 x 0.5 claims: {frames:?}"
    );
    assert!(count(&frames, rate_limited) >= 8);
    // The members' budget is untouched.
    send_frame(
        &mut b,
        &Frame::Broadcast {
            org: org.clone(),
            body: vec![1],
        },
    )
    .await;
    let (frames, _) = drain(&mut b, Duration::from_millis(300)).await;
    assert_eq!(
        count(&frames, |f| matches!(f, Frame::Receipt { .. })),
        1,
        "{frames:?}"
    );
    assert_eq!(count(&frames, rate_limited), 0);
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn outboxes_have_a_frame_and_byte_budget() {
    let big = |n: usize| Frame::Deliver {
        org: "o".into(),
        from: "f".into(),
        body: vec![0; n],
    };
    // One frame always fits; more only within the byte budget.
    let (tx, mut rx) = Tx::new(2000);
    assert!(queue(&tx, big(5000)));
    assert!(!queue(&tx, big(10)));
    let (_, n) = rx.try_recv().unwrap();
    tx.queued.fetch_sub(n, Ordering::Relaxed);
    assert!(queue(&tx, big(1000)));
    assert!(!queue(&tx, big(1000)), "over the byte budget");
    // And within the frame budget.
    let (tx, _rx) = Tx::new(usize::MAX);
    for _ in 0..MAX_QUEUED_FRAMES {
        assert!(queue(&tx, big(0)));
    }
    assert!(!queue(&tx, big(0)), "over the frame budget");
}

/// req: REQ-RELAY-006
#[test]
fn receipts_leave_out_devices_whose_outbox_is_full() {
    let state = new_state(Duration::from_secs(10));
    let mut r = state.lock().unwrap();
    // Two devices; nobody reads `stuck`'s outbox, as with a device that stopped reading.
    let (stuck, _rx1) = Tx::new(usize::MAX);
    let (fine, _rx2) = Tx::new(usize::MAX);
    while queue(&stuck, error("x", String::new())) {}
    r.conns.insert("stuck".into(), Conn { id: 1, tx: stuck });
    r.conns.insert("fine".into(), Conn { id: 2, tx: fine });
    let to = ["stuck".to_string(), "fine".to_string(), "gone".to_string()];
    assert_eq!(fan_out(&r, &to, || error("y", String::new())), ["fine"]);
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn silent_connections_are_closed_and_answering_ones_kept() {
    let url = start_with(Limits {
        idle_timeout: Duration::from_millis(300),
        ..Limits::default()
    })
    .await;
    let (root, ka, kb) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    let mut b = login(&url, &kb).await;
    join(&mut b, &root, &kb).await;
    // b keeps reading, so its client answers the relay's pings.
    let until = Instant::now() + Duration::from_millis(1200);
    while Instant::now() < until {
        if let Ok(Some(Ok(tungstenite::Message::Close(_))) | None | Some(Err(_))) =
            tokio::time::timeout(Duration::from_millis(100), b.next()).await
        {
            panic!("a device that answers pings stays");
        }
    }
    // a read nothing all that time, so it never answered: closed. (Its client may
    // fail answering the queued pings before it reads the `idle-timeout` error.)
    let (frames, closed) = drain(&mut a, Duration::from_secs(2)).await;
    assert!(closed, "{frames:?}");
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn connections_per_client_address_are_limited() {
    let state = new_state_with(
        Duration::from_secs(10),
        Limits {
            max_connections_per_ip: 2,
            ..Limits::default()
        },
    );
    let url = start_state(state).await;
    let first = connect(&url).await;
    let _second = connect(&url).await;
    assert!(connect_async(&url).await.is_err(), "HTTP 429");
    drop(first);
    for _ in 0..50 {
        if connect_async(&url).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the slot was never freed");
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn behind_a_proxy_the_forwarded_address_counts() {
    use tungstenite::client::IntoClientRequest;
    let state = new_state_with(
        Duration::from_secs(10),
        Limits {
            max_connections_per_ip: 1,
            client_ip_header: Some("x-forwarded-for".into()),
            ..Limits::default()
        },
    );
    let url = start_state(state).await;
    let from = |ip: &str| {
        let mut req = url.as_str().into_client_request().unwrap();
        req.headers_mut().insert(
            "x-forwarded-for",
            format!("10.0.0.9, {ip}").parse().unwrap(),
        );
        req
    };
    let _a = connect_async(from("192.0.2.1")).await.unwrap();
    let _b = connect_async(from("192.0.2.2")).await.unwrap();
    assert!(connect_async(from("192.0.2.1")).await.is_err());
}

#[test]
fn client_addresses_use_the_proxys_entry_and_group_ipv6_by_64() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    let mut h = HeaderMap::new();
    h.append(
        "x-forwarded-for",
        "203.0.113.5, 198.51.100.7".parse().unwrap(),
    );
    let ip = |h: &HeaderMap, name| client_ip(peer, h, name).unwrap().to_string();
    assert_eq!(ip(&h, None), "127.0.0.1");
    assert_eq!(ip(&h, Some("x-forwarded-for")), "198.51.100.7");
    assert_eq!(ip(&HeaderMap::new(), Some("x-forwarded-for")), "127.0.0.1");
    h.insert("x-forwarded-for", "2001:db8:1:2:3:4:5:6".parse().unwrap());
    assert_eq!(ip(&h, Some("x-forwarded-for")), "2001:db8:1:2::");
    h.insert("x-forwarded-for", "garbage".parse().unwrap());
    assert_eq!(ip(&h, Some("x-forwarded-for")), "127.0.0.1");
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn orgs_per_announce_and_per_device_are_capped() {
    let url = start(Duration::from_secs(10)).await;
    let key = DeviceKey::generate();
    let mut ws = login(&url, &key).await;
    let pending = |n: usize| Frame::Announce {
        orgs: (0..n)
            .map(|_| Membership {
                org: org_id(&DeviceKey::generate()),
                proof: String::new(),
                always_on: false,
                revoked: vec![],
            })
            .collect(),
    };
    send_frame(&mut ws, &pending(MAX_ORGS_PER_ANNOUNCE + 1)).await;
    expect_error(next_frame(&mut ws).await, "too-many-orgs");
    send_frame(&mut ws, &pending(MAX_ORGS_PER_DEVICE)).await;
    send_frame(&mut ws, &pending(1)).await;
    expect_error(next_frame(&mut ws).await, "too-many-orgs");
}

#[test]
fn the_relay_keeps_a_bounded_number_of_revocations() {
    let state = new_state(Duration::from_secs(10));
    let root = DeviceKey::generate();
    let org = org_id(&root);
    let notice = |dev: &DeviceKey| Revocation::issue_by_root(&root, dev.device_id(), 1).to_hex();
    let mut r = state.lock().unwrap();
    let rev = |n: &str| verify_notice(&root.device_id(), n).unwrap();
    let first = notice(&DeviceKey::generate());
    assert_eq!(
        remember_verified(&mut r, &org, &rev(&first), &first, false),
        Ok(true)
    );
    r.revoked_total = MAX_REVOKED_TOTAL;
    let next = notice(&DeviceKey::generate());
    assert!(remember_verified(&mut r, &org, &rev(&next), &next, false).is_err());
    // Known devices are still recognised.
    assert_eq!(
        remember_verified(&mut r, &org, &rev(&first), &first, false),
        Ok(false)
    );
}

/// req: REQ-RELAY-006
#[tokio::test]
async fn rate_buckets_of_orgs_without_online_devices_are_forgotten() {
    let state = new_state(Duration::from_secs(10));
    let url = start_state(state.clone()).await;
    let (root, ka, kp) = (
        DeviceKey::generate(),
        DeviceKey::generate(),
        DeviceKey::generate(),
    );
    let org = org_id(&root);
    let mut a = login(&url, &ka).await;
    join(&mut a, &root, &ka).await;
    let mut p = login(&url, &kp).await;
    announce(&mut p, &org, String::new()).await;
    send_frame(&mut p, &claim(&org)).await;
    send_frame(
        &mut a,
        &Frame::Broadcast {
            org: org.clone(),
            body: vec![1],
        },
    )
    .await;
    let _ = next_frame(&mut p).await;
    while !matches!(next_frame(&mut a).await, Some(Frame::Receipt { .. })) {}
    {
        let r = state.lock().unwrap();
        assert!(r.org_buckets.contains_key(&org) && r.pending_buckets.contains_key(&org));
    }
    drop(a);
    drop(p);
    for _ in 0..100 {
        {
            let r = state.lock().unwrap();
            if r.org_buckets.is_empty() && r.pending_buckets.is_empty() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the buckets were kept");
}

// ---- configuration and sizing (pinned before the module split) ----

/// req: REQ-RELAY-006
#[test]
fn limits_are_read_from_the_environment_and_bad_values_fall_back() {
    let d = Limits::default();
    let none = Limits::from_lookup(|_| None);
    assert_eq!(none.device_burst, d.device_burst);
    assert_eq!(none.max_connections, d.max_connections);
    assert_eq!(none.client_ip_header, None);

    let env = |name: &str| {
        Some(
            match name {
                "KITH_RELAY_DEVICE_BURST" => "7",
                "KITH_RELAY_MAX_CONNECTIONS" => "not a number",
                "KITH_RELAY_WRITE_TIMEOUT_SECS" => "3",
                "KITH_RELAY_IDLE_TIMEOUT_SECS" => "9",
                "KITH_RELAY_MAX_CONNECTIONS_PER_IP" => "2",
                "KITH_RELAY_CLIENT_IP_HEADER" => "  X-Forwarded-For ",
                _ => return None,
            }
            .to_string(),
        )
    };
    let l = Limits::from_lookup(env);
    assert_eq!(l.device_burst, 7.0);
    assert_eq!(l.max_connections, d.max_connections, "unparsable: default");
    assert_eq!(l.write_timeout, Duration::from_secs(3));
    assert_eq!(l.idle_timeout, Duration::from_secs(9));
    assert_eq!(l.max_connections_per_ip, 2);
    assert_eq!(l.client_ip_header.as_deref(), Some("x-forwarded-for"));
    // An empty header name means "not set".
    let l = Limits::from_lookup(|n| (n == "KITH_RELAY_CLIENT_IP_HEADER").then(|| " ".into()));
    assert_eq!(l.client_ip_header, None);
}

#[test]
fn queued_frames_are_sized_by_what_they_carry() {
    let body = |n: usize| vec![0u8; n];
    let base = approx_size(&Frame::Receipt { delivered: vec![] });
    assert_eq!(base, 256);
    for f in [
        Frame::Broadcast {
            org: "o".into(),
            body: body(1000),
        },
        Frame::Direct {
            org: "o".into(),
            to: "t".into(),
            body: body(1000),
        },
        Frame::SyncRequest {
            org: "o".into(),
            body: body(1000),
        },
        Frame::Deliver {
            org: "o".into(),
            from: "f".into(),
            body: body(1000),
        },
        Frame::ClaimDeliver {
            org: "o".into(),
            from: "f".into(),
            body: body(1000),
        },
    ] {
        assert_eq!(approx_size(&f), base + 1000, "{f:?}");
    }
    let two = vec!["a".to_string(), "b".to_string()];
    assert_eq!(
        approx_size(&Frame::Presence {
            org: "o".into(),
            online: two.clone()
        }),
        base + 160
    );
    assert_eq!(approx_size(&Frame::Receipt { delivered: two }), base + 160);
    assert_eq!(
        approx_size(&Frame::Error {
            code: "c".into(),
            message: "four".into()
        }),
        base + 4
    );
}
