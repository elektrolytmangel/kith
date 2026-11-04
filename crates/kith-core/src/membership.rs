//! Organization membership and invitations (phase 5, ADR 0005).
//!
//! - **Org root key**: an Ed25519 key created with the organization. Its public
//!   key *is* the org ID (hex), so anyone, the relay included, can check a
//!   membership proof against the org ID alone.
//! - **[`MembershipCert`]**: "device D is a member (or admin) of org O", signed by
//!   the root key or by an admin. A [`CertChain`] has at most two certificates:
//!   root → admin, or root → admin → member. Only the root makes admins.
//! - **[`Invite`]**: a one-time, expiring link from an admin with a random secret.
//!   The new device proves it knows the secret with [`Invite::claim_proof`] over
//!   its MLS KeyPackage; both screens can show [`Invite::short_code`].
//!
//! Revocation is not expressed here (phase 6, policy object): a removed device
//! keeps a valid certificate for the relay but cannot read anything (MLS).

use sha2::{Digest, Sha256};

use crate::{DeviceId, Signer, verify_signature};

/// Membership errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MembershipError {
    /// Malformed certificate, chain or invite link.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// A signature does not verify.
    #[error("bad signature")]
    BadSignature,
    /// The chain does not prove what was asked (wrong org, device or issuer).
    #[error("not a valid membership proof: {0}")]
    Invalid(&'static str),
}

const CERT_DOMAIN: &[u8] = b"kith/membership/v1\0";
/// Encoded size of one certificate.
pub const CERT_LEN: usize = 32 * 3 + 1 + 8 + 64;

/// "`device` belongs to `org`", signed by `issuer` (the root key or an admin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipCert {
    /// The org's root public key (= org ID).
    pub org: DeviceId,
    /// The member device.
    pub device: DeviceId,
    /// Who signed: the root key, or an admin device.
    pub issuer: DeviceId,
    /// True if `device` may invite and admit others. Only the root grants it.
    pub admin: bool,
    /// When it was issued (issuer's clock, informational).
    pub issued_ms: u64,
    /// Ed25519 signature by `issuer`.
    pub signature: [u8; 64],
}

impl MembershipCert {
    /// Issue a certificate signed by `issuer` (the root key or an admin's device key).
    pub fn issue(
        issuer: &dyn Signer,
        org: DeviceId,
        device: DeviceId,
        admin: bool,
        issued_ms: u64,
    ) -> Self {
        let mut c = Self {
            org,
            device,
            issuer: issuer.device_id(),
            admin,
            issued_ms,
            signature: [0; 64],
        };
        c.signature = issuer.sign(&c.signed_bytes());
        c
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(CERT_DOMAIN.len() + CERT_LEN);
        m.extend_from_slice(CERT_DOMAIN);
        m.extend_from_slice(&self.org.0);
        m.extend_from_slice(&self.device.0);
        m.extend_from_slice(&self.issuer.0);
        m.push(self.admin as u8);
        m.extend_from_slice(&self.issued_ms.to_be_bytes());
        m
    }

    fn verify_signature(&self) -> Result<(), MembershipError> {
        verify_signature(&self.issuer, &self.signed_bytes(), &self.signature)
            .map_err(|_| MembershipError::BadSignature)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.org.0);
        out.extend_from_slice(&self.device.0);
        out.extend_from_slice(&self.issuer.0);
        out.push(self.admin as u8);
        out.extend_from_slice(&self.issued_ms.to_be_bytes());
        out.extend_from_slice(&self.signature);
    }

    fn decode(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() != CERT_LEN {
            return Err(MembershipError::Malformed("certificate length"));
        }
        let id = |r: std::ops::Range<usize>| DeviceId(b[r].try_into().expect("32 bytes"));
        let admin = match b[96] {
            0 => false,
            1 => true,
            _ => return Err(MembershipError::Malformed("admin flag")),
        };
        Ok(Self {
            org: id(0..32),
            device: id(32..64),
            issuer: id(64..96),
            admin,
            issued_ms: u64::from_be_bytes(b[97..105].try_into().expect("8 bytes")),
            signature: b[105..].try_into().expect("64 bytes"),
        })
    }
}

/// A device's proof of membership: its own certificate, preceded by its issuer's
/// admin certificate when the issuer is not the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertChain(pub Vec<MembershipCert>);

/// What a valid chain proves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proven {
    /// The device is an admin of the org.
    pub admin: bool,
}

impl CertChain {
    /// The device's own (last) certificate.
    pub fn leaf(&self) -> Option<&MembershipCert> {
        self.0.last()
    }

    /// Check that this chain proves `device` is a member of `org` (whose ID is the
    /// root public key). No state needed: the relay calls this on `announce`.
    pub fn verify(&self, org: &DeviceId, device: &DeviceId) -> Result<Proven, MembershipError> {
        let leaf = match self.0.as_slice() {
            [leaf] | [_, leaf] => leaf,
            _ => {
                return Err(MembershipError::Invalid(
                    "chain must have 1 or 2 certificates",
                ));
            }
        };
        if self.0.iter().any(|c| &c.org != org) {
            return Err(MembershipError::Invalid("certificate for another org"));
        }
        if &leaf.device != device {
            return Err(MembershipError::Invalid("certificate for another device"));
        }
        for c in &self.0 {
            c.verify_signature()?;
        }
        match self.0.as_slice() {
            [leaf] if &leaf.issuer == org => {}
            [admin, leaf] => {
                if &admin.issuer != org || !admin.admin || admin.device != leaf.issuer {
                    return Err(MembershipError::Invalid("issuer is not a root-made admin"));
                }
                if leaf.admin {
                    return Err(MembershipError::Invalid("only the root makes admins"));
                }
            }
            _ => return Err(MembershipError::Invalid("not issued by the root key")),
        }
        Ok(Proven { admin: leaf.admin })
    }

    /// Hex encoding, as sent in `announce` (`Membership::proof`).
    pub fn to_hex(&self) -> String {
        let mut b = Vec::with_capacity(self.0.len() * CERT_LEN);
        for c in &self.0 {
            c.encode(&mut b);
        }
        hex::encode(b)
    }

    /// Parse [`Self::to_hex`].
    pub fn from_hex(s: &str) -> Result<Self, MembershipError> {
        let b = hex::decode(s).map_err(|_| MembershipError::Malformed("not hex"))?;
        if b.is_empty() || b.len() % CERT_LEN != 0 || b.len() > 2 * CERT_LEN {
            return Err(MembershipError::Malformed("chain length"));
        }
        b.chunks(CERT_LEN)
            .map(MembershipCert::decode)
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

// ---- invitations ----

/// A one-time invitation to an org (REQ-INV-001). Share [`Invite::to_link`] as a
/// link or QR code; anyone who has it can claim it once before it expires, so
/// treat it like a password.
#[derive(Clone, PartialEq, Eq)]
pub struct Invite {
    /// The org (root public key).
    pub org: DeviceId,
    /// Relay WebSocket URL the new device connects to.
    pub relay: String,
    /// Public token naming the invite (not secret).
    pub token: [u8; 16],
    /// The secret the claim proves knowledge of.
    pub secret: [u8; 32],
    /// Expiry, milliseconds since the Unix epoch.
    pub expires_ms: u64,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("org", &self.org)
            .field("relay", &self.relay)
            .field("token", &hex::encode(self.token))
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

const LINK_PREFIX: &str = "kith://invite/v1?";

impl Invite {
    /// A fresh invite valid until `expires_ms`.
    pub fn new(org: DeviceId, relay: &str, expires_ms: u64) -> Self {
        Self {
            org,
            relay: relay.into(),
            token: crate::random_bytes(),
            secret: crate::random_bytes(),
            expires_ms,
        }
    }

    /// `kith://invite/v1?org=…&relay=…&token=…&secret=…&expires=…`
    pub fn to_link(&self) -> String {
        format!(
            "{LINK_PREFIX}org={}&relay={}&token={}&secret={}&expires={}",
            self.org.to_hex(),
            percent_encode(&self.relay),
            hex::encode(self.token),
            hex::encode(self.secret),
            self.expires_ms
        )
    }

    /// Parse [`Self::to_link`].
    pub fn parse(link: &str) -> Result<Self, MembershipError> {
        let query = link
            .trim()
            .strip_prefix(LINK_PREFIX)
            .ok_or(MembershipError::Malformed("not a kith invite link"))?;
        let mut org = None;
        let mut relay = None;
        let mut token = None;
        let mut secret = None;
        let mut expires = None;
        for pair in query.split('&') {
            let (k, v) = pair
                .split_once('=')
                .ok_or(MembershipError::Malformed("query pair"))?;
            match k {
                "org" => org = DeviceId::from_hex(v).ok(),
                "relay" => relay = percent_decode(v),
                "token" => token = hex::decode(v).ok().and_then(|b| b.try_into().ok()),
                "secret" => secret = hex::decode(v).ok().and_then(|b| b.try_into().ok()),
                "expires" => expires = v.parse().ok(),
                _ => {} // ignore unknown keys from newer versions
            }
        }
        Ok(Self {
            org: org.ok_or(MembershipError::Malformed("org"))?,
            relay: relay.ok_or(MembershipError::Malformed("relay"))?,
            token: token.ok_or(MembershipError::Malformed("token"))?,
            secret: secret.ok_or(MembershipError::Malformed("secret"))?,
            expires_ms: expires.ok_or(MembershipError::Malformed("expires"))?,
        })
    }

    /// True once `now_ms` is past the expiry.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    /// The claim's proof that the sender knows the secret, bound to the KeyPackage
    /// it wants to be added with (REQ-INV-002). A relay that swaps the KeyPackage
    /// cannot produce it.
    pub fn claim_proof(&self, key_package: &[u8]) -> [u8; 32] {
        self.mac(b"kith/invite-claim/v1\0", key_package)
    }

    /// Check a claim's proof in constant time.
    pub fn verify_claim(&self, key_package: &[u8], proof: &[u8; 32]) -> bool {
        let want = self.claim_proof(key_package);
        want.iter()
            .zip(proof)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// A 6-digit code both devices can show (REQ-INV-003). If they match, the
    /// admin is adding the device the user holds, not one that obtained the link.
    pub fn short_code(&self, key_package: &[u8]) -> String {
        let m = self.mac(b"kith/invite-code/v1\0", key_package);
        let n = u32::from_be_bytes(m[..4].try_into().expect("4 bytes")) % 1_000_000;
        format!("{n:06}")
    }

    fn mac(&self, domain: &[u8], key_package: &[u8]) -> [u8; 32] {
        let mut msg = Vec::with_capacity(domain.len() + 16 + 32);
        msg.extend_from_slice(domain);
        msg.extend_from_slice(&self.token);
        msg.extend_from_slice(&Sha256::digest(key_package));
        hmac_sha256(&self.secret, &msg)
    }
}

/// HMAC-SHA256 (RFC 2104) with a key of at most one block (64 bytes).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 64, "HMAC key longer than one block");
    let mut k = [0u8; 64];
    k[..key.len()].copy_from_slice(key);
    let pad = |b: u8| k.map(|x| x ^ b);
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(msg)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
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
        for bad in ["", "zz", "00", &"00".repeat(CERT_LEN * 3)] {
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
        let code = inv.short_code(b"kp-1");
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(code, inv.short_code(b"kp-1"));
        assert_ne!(code, other.short_code(b"kp-1"));
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
}
