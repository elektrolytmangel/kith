use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

struct TestKey(SigningKey);
impl Signer for TestKey {
    fn device_id(&self) -> DeviceId {
        DeviceId(self.0.verifying_key().to_bytes())
    }
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

fn key() -> TestKey {
    TestKey(SigningKey::from_bytes(&crate::random_bytes()))
}

/// req: REQ-INV-004
#[test]
fn revocations_need_an_admin_and_round_trip() {
    let (root, admin, member, gone) = (key(), key(), key(), key());
    let org = root.device_id();
    let admin_chain = CertChain(vec![MembershipCert::issue(
        &root,
        org,
        admin.device_id(),
        true,
        1,
    )]);
    let r = Revocation::issue(&admin, admin_chain.clone(), org, gone.device_id(), 5);
    assert_eq!(r.verify(&org), Ok(()));
    assert_eq!(Revocation::from_hex(&r.to_hex()), Ok(r.clone()));
    // Another org, a tampered target, a member as issuer, truncated data.
    assert!(r.verify(&member.device_id()).is_err());
    let mut forged = r.clone();
    forged.device = member.device_id();
    assert_eq!(forged.verify(&org), Err(MembershipError::BadSignature));
    let member_chain = CertChain(vec![
        admin_chain.0[0].clone(),
        MembershipCert::issue(&admin, org, member.device_id(), false, 2),
    ]);
    let by_member = Revocation::issue(&member, member_chain, org, gone.device_id(), 5);
    assert!(by_member.verify(&org).is_err());
    assert!(Revocation::from_hex(&r.to_hex()[..100]).is_err());
    // Own devices go with their member.
    let own = CertChain(vec![
        admin_chain.0[0].clone(),
        MembershipCert::issue(&admin, org, member.device_id(), false, 2),
        MembershipCert::issue_own(&member, org, gone.device_id(), 3),
    ]);
    assert!(own.touches(|d| d == &member.device_id()));
    assert!(!own.touches(|d| d == &DeviceId([9; 32])));
}

/// req: REQ-RELAY-004
/// req: REQ-ID-003
#[test]
fn root_and_admin_issued_chains_verify() {
    let (root, admin, member) = (key(), key(), key());
    let org = root.device_id();
    let admin_cert = MembershipCert::issue(&root, org, admin.device_id(), true, 1);
    let by_root = CertChain(vec![admin_cert.clone()]);
    assert_eq!(
        by_root.verify(&org, &admin.device_id()),
        Ok(Proven { admin: true })
    );
    let member_cert = MembershipCert::issue(&admin, org, member.device_id(), false, 2);
    let chain = CertChain(vec![admin_cert, member_cert]);
    assert_eq!(
        chain.verify(&org, &member.device_id()),
        Ok(Proven { admin: false })
    );
    assert_eq!(CertChain::from_hex(&chain.to_hex()).unwrap(), chain);
}

/// req: REQ-ID-002
#[test]
fn members_certify_only_their_own_devices() {
    let (root, admin, member, phone, stranger) = (key(), key(), key(), key(), key());
    let org = root.device_id();
    let admin_cert = MembershipCert::issue(&root, org, admin.device_id(), true, 1);
    let member_cert = MembershipCert::issue(&admin, org, member.device_id(), false, 2);
    let own = MembershipCert::issue_own(&member, org, phone.device_id(), 3);
    let chain = CertChain(vec![admin_cert.clone(), member_cert.clone(), own.clone()]);
    assert_eq!(
        chain.verify(&org, &phone.device_id()),
        Ok(Proven { admin: false })
    );
    assert_eq!(CertChain::from_hex(&chain.to_hex()).unwrap(), chain);
    // A root-certified member and an admin can link their own devices too.
    let root_member = MembershipCert::issue(&root, org, member.device_id(), false, 1);
    assert!(
        CertChain(vec![root_member.clone(), own.clone()])
            .verify(&org, &phone.device_id())
            .is_ok()
    );
    let admin_own = MembershipCert::issue_own(&admin, org, phone.device_id(), 3);
    assert!(
        CertChain(vec![admin_cert.clone(), admin_own.clone()])
            .verify(&org, &phone.device_id())
            .is_ok()
    );
    // The flag is signed: a plain member certificate cannot be passed off as an
    // own-device one or the other way round.
    let mut forged = own.clone();
    forged.own = false;
    assert!(
        CertChain(vec![root_member.clone(), forged])
            .verify(&org, &phone.device_id())
            .is_err()
    );
    // A member cannot admit a plain member, nor make admins.
    let plain = MembershipCert::issue(&member, org, stranger.device_id(), false, 3);
    assert!(
        CertChain(vec![admin_cert.clone(), member_cert.clone(), plain])
            .verify(&org, &stranger.device_id())
            .is_err()
    );
    let admin_by_member = MembershipCert::issue(&member, org, stranger.device_id(), true, 3);
    assert!(
        CertChain(vec![
            admin_cert.clone(),
            member_cert.clone(),
            admin_by_member
        ])
        .verify(&org, &stranger.device_id())
        .is_err()
    );
    // An own device cannot certify more devices, and an own certificate cannot
    // come straight from the root.
    let more = MembershipCert::issue_own(&phone, org, stranger.device_id(), 4);
    assert!(
        CertChain(vec![
            admin_cert.clone(),
            member_cert.clone(),
            own.clone(),
            more
        ])
        .verify(&org, &stranger.device_id())
        .is_err()
    );
    let root_own = MembershipCert::issue_own(&root, org, phone.device_id(), 1);
    assert!(
        CertChain(vec![root_own])
            .verify(&org, &phone.device_id())
            .is_err()
    );
    // Chain links must connect.
    assert!(
        CertChain(vec![admin_cert, own])
            .verify(&org, &phone.device_id())
            .is_err()
    );
}

/// req: REQ-RELAY-004
#[test]
fn forged_or_misused_chains_fail() {
    let (root, admin, member, stranger) = (key(), key(), key(), key());
    let org = root.device_id();
    let admin_cert = MembershipCert::issue(&root, org, admin.device_id(), true, 1);
    let member_cert = MembershipCert::issue(&admin, org, member.device_id(), false, 2);
    let ok = CertChain(vec![admin_cert.clone(), member_cert.clone()]);
    // Someone else's chain.
    assert!(ok.verify(&org, &stranger.device_id()).is_err());
    // Another org.
    assert!(
        ok.verify(&stranger.device_id(), &member.device_id())
            .is_err()
    );
    // Self-signed membership.
    let selfish = CertChain(vec![MembershipCert::issue(
        &stranger,
        org,
        stranger.device_id(),
        true,
        1,
    )]);
    assert!(selfish.verify(&org, &stranger.device_id()).is_err());
    // Issued by a non-admin member.
    let by_member = MembershipCert::issue(&member, org, stranger.device_id(), false, 3);
    let not_admin = MembershipCert::issue(&root, org, member.device_id(), false, 1);
    assert!(
        CertChain(vec![not_admin, by_member])
            .verify(&org, &stranger.device_id())
            .is_err()
    );
    // An admin cannot make admins.
    let made_admin = MembershipCert::issue(&admin, org, stranger.device_id(), true, 3);
    assert!(
        CertChain(vec![admin_cert.clone(), made_admin])
            .verify(&org, &stranger.device_id())
            .is_err()
    );
    // Tampering with any field breaks the signature.
    let mut tampered = member_cert.clone();
    tampered.admin = true;
    assert!(
        CertChain(vec![admin_cert.clone(), tampered])
            .verify(&org, &member.device_id())
            .is_err()
    );
    // Wrong lengths and garbage.
    assert!(CertChain(vec![]).verify(&org, &member.device_id()).is_err());
    assert!(
        CertChain(vec![admin_cert.clone(), admin_cert.clone(), member_cert])
            .verify(&org, &member.device_id())
            .is_err()
    );
    for bad in ["", "zz", "00", &"00".repeat(CERT_LEN * 4)] {
        assert!(CertChain::from_hex(bad).is_err(), "{bad:.10}");
    }
}

/// req: REQ-INV-001
#[test]
fn invite_links_roundtrip() {
    let inv = Invite::new(
        key().device_id(),
        "wss://relay.example.com:8443/v1/ws?x=1&y",
        99,
    );
    let link = inv.to_link();
    assert!(link.starts_with("kith://invite/v1?"));
    assert_eq!(Invite::parse(&link).unwrap(), inv);
    let me = key().device_id();
    let own = Invite::new_own_device(inv.org, "ws://r", 5, me);
    assert!(own.to_link().ends_with(&format!("&own={}", me.to_hex())));
    assert_eq!(Invite::parse(&own.to_link()).unwrap(), own);
    assert!(Invite::parse(&link).unwrap().own_device.is_none());
    assert!(Invite::parse(&own.to_link().replace(&me.to_hex(), "zz")).is_err());
    assert!(Invite::parse("https://example.com").is_err());
    assert!(Invite::parse(&link.replace("token=", "tokn=")).is_err());
    assert!(inv.is_expired(99) && !inv.is_expired(98));
    assert!(!format!("{inv:?}").contains(&hex::encode(inv.secret)));
}

/// req: REQ-INV-002
/// req: REQ-INV-003
#[test]
fn claims_prove_the_secret_for_one_key_package() {
    let inv = Invite::new(key().device_id(), "ws://r", 99);
    let proof = inv.claim_proof(b"kp-1");
    assert!(inv.verify_claim(b"kp-1", &proof));
    assert!(
        !inv.verify_claim(b"kp-2", &proof),
        "bound to the KeyPackage"
    );
    let mut other = inv.clone();
    other.secret[0] ^= 1;
    assert!(!other.verify_claim(b"kp-1", &proof), "needs the secret");
    let n = [7u8; 32];
    let code = inv.short_code(b"kp-1", &n);
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|b| b.is_ascii_digit()));
    assert_eq!(code, inv.short_code(b"kp-1", &n));
    assert_ne!(code, other.short_code(b"kp-1", &n));
    // The admin's nonce changes it: it cannot be known before the claim is sent.
    let codes: std::collections::HashSet<_> = (0..20u8)
        .map(|i| inv.short_code(b"kp-1", &[i; 32]))
        .collect();
    assert!(codes.len() > 15);
    assert_ne!(
        inv.nonce_signed_bytes(b"kp-1", &n),
        inv.nonce_signed_bytes(b"kp-2", &n)
    );
}

/// RFC 4231 test cases 1 and 2 (HMAC-SHA256).
#[test]
fn hmac_matches_rfc_4231() {
    assert_eq!(
        hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}
