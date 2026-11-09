//! Organization membership and invitations (phase 5, ADR 0005).
//!
//! - **Org root key**: an Ed25519 key created with the organization. Its public
//!   key *is* the org ID (hex), so anyone, the relay included, can check a
//!   membership proof against the org ID alone.
//! - **[`MembershipCert`]**: "device D is a member (or admin) of org O", signed by
//!   the root key or by an admin. A [`CertChain`] has at most three certificates:
//!   root → admin, root → admin → member, or root → (admin →) member → own device
//!   (ADR 0011: a member certifies its own additional device). Only the root makes
//!   admins.
//! - **[`Invite`]**: a one-time, expiring link from an admin with a random secret.
//!   The new device proves it knows the secret with [`Invite::claim_proof`] over
//!   its MLS KeyPackage; both screens can show [`Invite::short_code`].
//!
//! - **[`Revocation`]**: an admin-signed "device D was removed", which the relay
//!   keeps in RAM and checks on `announce` (REQ-INV-004). Certificates themselves do
//!   not expire.

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
    /// True for a member's own additional device (ADR 0011): signed by the member
    /// itself, never an admin, and it cannot certify further devices.
    pub own: bool,
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
            own: false,
            issued_ms,
            signature: [0; 64],
        };
        c.signature = issuer.sign(&c.signed_bytes());
        c
    }

    /// Issue the certificate of `issuer`'s own additional device (ADR 0011).
    pub fn issue_own(issuer: &dyn Signer, org: DeviceId, device: DeviceId, issued_ms: u64) -> Self {
        let mut c = Self {
            org,
            device,
            issuer: issuer.device_id(),
            admin: false,
            own: true,
            issued_ms,
            signature: [0; 64],
        };
        c.signature = issuer.sign(&c.signed_bytes());
        c
    }

    /// The flag byte: 0 member, 1 admin, 2 own device.
    fn kind(&self) -> u8 {
        if self.own { 2 } else { self.admin as u8 }
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(CERT_DOMAIN.len() + CERT_LEN);
        m.extend_from_slice(CERT_DOMAIN);
        m.extend_from_slice(&self.org.0);
        m.extend_from_slice(&self.device.0);
        m.extend_from_slice(&self.issuer.0);
        m.push(self.kind());
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
        out.push(self.kind());
        out.extend_from_slice(&self.issued_ms.to_be_bytes());
        out.extend_from_slice(&self.signature);
    }

    fn decode(b: &[u8]) -> Result<Self, MembershipError> {
        if b.len() != CERT_LEN {
            return Err(MembershipError::Malformed("certificate length"));
        }
        let id = |at: usize| {
            crate::array_at(b, at)
                .map(DeviceId)
                .ok_or(MembershipError::Malformed("certificate"))
        };
        let (admin, own) = match b[96] {
            0 => (false, false),
            1 => (true, false),
            2 => (false, true),
            _ => return Err(MembershipError::Malformed("admin flag")),
        };
        Ok(Self {
            org: id(0)?,
            device: id(32)?,
            issuer: id(64)?,
            admin,
            own,
            issued_ms: u64::from_be_bytes(
                crate::array_at(b, 97).ok_or(MembershipError::Malformed("certificate"))?,
            ),
            signature: crate::array_at(b, 105).ok_or(MembershipError::Malformed("certificate"))?,
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
        let Some(leaf) = self.0.last().filter(|_| (1..=3).contains(&self.0.len())) else {
            return Err(MembershipError::Invalid(
                "chain must have 1 to 3 certificates",
            ));
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
        // The first certificate comes from the root and is never an own-device one.
        let first = &self.0[0];
        if &first.issuer != org || first.own {
            return Err(MembershipError::Invalid("not issued by the root key"));
        }
        for pair in self.0.windows(2) {
            let (issuer, c) = (&pair[0], &pair[1]);
            if issuer.device != c.issuer {
                return Err(MembershipError::Invalid("broken chain"));
            }
            if c.admin {
                return Err(MembershipError::Invalid("only the root makes admins"));
            }
            if issuer.own {
                return Err(MembershipError::Invalid("an own device cannot certify"));
            }
            // Members may only certify their own devices; admins also admit members.
            if !issuer.admin && !c.own {
                return Err(MembershipError::Invalid("issuer is not a root-made admin"));
            }
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
        if b.is_empty() || b.len() % CERT_LEN != 0 || b.len() > 3 * CERT_LEN {
            return Err(MembershipError::Malformed("chain length"));
        }
        b.chunks(CERT_LEN)
            .map(MembershipCert::decode)
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

// ---- revocation ----

const REVOKE_DOMAIN: &[u8] = b"kith/revoke/v1\0";
/// Encoded size of a revocation without its issuer chain.
const REVOKE_LEN: usize = 32 * 3 + 8 + 64;

/// "Device `device` is no longer a member of `org`", signed by an admin and
/// checkable from the org ID alone (REQ-INV-004). The relay keeps these in RAM and
/// refuses the device (and every device certified through it); admin and always-on
/// clients hand them back after a relay restart. The policy object stays the source
/// of truth for writes; this only closes the relay-level gap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The org (its root public key).
    pub org: DeviceId,
    /// The removed device.
    pub device: DeviceId,
    /// The admin device that signed, or the org root key itself.
    pub issuer: DeviceId,
    /// When it was signed (issuer's clock, informational).
    pub issued_ms: u64,
    /// Ed25519 signature by `issuer`.
    pub signature: [u8; 64],
    /// The issuer's membership chain, proving it is an admin; empty when the
    /// root key signed.
    pub chain: CertChain,
}

impl Revocation {
    /// Sign a revocation of `device`. `chain` is the issuer's own admin chain.
    pub fn issue(
        issuer: &dyn Signer,
        chain: CertChain,
        org: DeviceId,
        device: DeviceId,
        issued_ms: u64,
    ) -> Self {
        let mut r = Self {
            org,
            device,
            issuer: issuer.device_id(),
            issued_ms,
            signature: [0; 64],
            chain,
        };
        r.signature = issuer.sign(&r.signed_bytes());
        r
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(REVOKE_DOMAIN.len() + REVOKE_LEN);
        m.extend_from_slice(REVOKE_DOMAIN);
        m.extend_from_slice(&self.org.0);
        m.extend_from_slice(&self.device.0);
        m.extend_from_slice(&self.issuer.0);
        m.extend_from_slice(&self.issued_ms.to_be_bytes());
        m
    }

    /// Sign a revocation with the org root key (needed to remove an admin at the
    /// relay, ADR 0018).
    pub fn issue_by_root(root: &dyn Signer, device: DeviceId, issued_ms: u64) -> Self {
        let org = root.device_id();
        Self::issue(root, CertChain(vec![]), org, device, issued_ms)
    }

    /// True if the org root key signed it.
    pub fn by_root(&self) -> bool {
        self.issuer == self.org
    }

    /// Check the signature and that the issuer is an admin of `org` (or its root
    /// key). No state needed.
    pub fn verify(&self, org: &DeviceId) -> Result<(), MembershipError> {
        if &self.org != org {
            return Err(MembershipError::Invalid("revocation for another org"));
        }
        verify_signature(&self.issuer, &self.signed_bytes(), &self.signature)
            .map_err(|_| MembershipError::BadSignature)?;
        if self.by_root() {
            return if self.chain.0.is_empty() {
                Ok(())
            } else {
                Err(MembershipError::Invalid("a root revocation has no chain"))
            };
        }
        if !self.chain.verify(org, &self.issuer)?.admin {
            return Err(MembershipError::Invalid(
                "revocation issuer is not an admin",
            ));
        }
        Ok(())
    }

    /// Hex encoding (`Membership::revoked`).
    pub fn to_hex(&self) -> String {
        let mut b = Vec::with_capacity(REVOKE_LEN + CERT_LEN);
        b.extend_from_slice(&self.org.0);
        b.extend_from_slice(&self.device.0);
        b.extend_from_slice(&self.issuer.0);
        b.extend_from_slice(&self.issued_ms.to_be_bytes());
        b.extend_from_slice(&self.signature);
        for c in &self.chain.0 {
            c.encode(&mut b);
        }
        hex::encode(b)
    }

    /// Parse [`Self::to_hex`].
    pub fn from_hex(s: &str) -> Result<Self, MembershipError> {
        let b = hex::decode(s).map_err(|_| MembershipError::Malformed("not hex"))?;
        if b.len() < REVOKE_LEN
            || !(b.len() - REVOKE_LEN).is_multiple_of(CERT_LEN)
            || b.len() > REVOKE_LEN + 3 * CERT_LEN
        {
            return Err(MembershipError::Malformed("revocation length"));
        }
        let id = |at: usize| {
            crate::array_at(&b, at)
                .map(DeviceId)
                .ok_or(MembershipError::Malformed("revocation"))
        };
        let chain = b[REVOKE_LEN..]
            .chunks(CERT_LEN)
            .map(MembershipCert::decode)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            org: id(0)?,
            device: id(32)?,
            issuer: id(64)?,
            issued_ms: u64::from_be_bytes(
                crate::array_at(&b, 96).ok_or(MembershipError::Malformed("revocation"))?,
            ),
            signature: crate::array_at(&b, 104).ok_or(MembershipError::Malformed("revocation"))?,
            chain: CertChain(chain),
        })
    }
}

impl CertChain {
    /// True if any certificate in the chain is for a device in `revoked`: the device
    /// itself, or a device through which it was certified (a removed member takes
    /// its own devices with it).
    pub fn touches(&self, revoked: impl Fn(&DeviceId) -> bool) -> bool {
        self.0.iter().any(|c| revoked(&c.device))
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
    /// How many devices this invite may still admit (REQ-INV-005). 1 for the usual
    /// one-time invite. The issuing admin counts it down; the number in a shared
    /// link is only the capacity it was made with.
    pub uses: u32,
    /// Set if a member made this link to add one of its own devices (ADR 0011):
    /// the issuing device. It links the claimer to itself instead of admitting a
    /// new user, and the claim is routed to it, since it may not be an admin.
    pub own_device: Option<DeviceId>,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("org", &self.org)
            .field("relay", &self.relay)
            .field("token", &hex::encode(self.token))
            .field("expires_ms", &self.expires_ms)
            .field("uses", &self.uses)
            .field("own_device", &self.own_device)
            .finish_non_exhaustive()
    }
}

const LINK_PREFIX: &str = "kith://invite/v1?";

/// Most devices one multi-use invite may admit.
pub const MAX_INVITE_USES: u32 = 1000;

impl Invite {
    /// A fresh invite valid until `expires_ms`.
    pub fn new(org: DeviceId, relay: &str, expires_ms: u64) -> Self {
        Self {
            org,
            relay: relay.into(),
            token: crate::random_bytes(),
            secret: crate::random_bytes(),
            expires_ms,
            uses: 1,
            own_device: None,
        }
    }

    /// A fresh invite that admits up to `uses` devices (REQ-INV-005), clamped to
    /// `1..=`[`MAX_INVITE_USES`]. Everyone who holds the link can claim it, so the
    /// admin still checks each claim before admitting it.
    pub fn new_multi_use(org: DeviceId, relay: &str, expires_ms: u64, uses: u32) -> Self {
        Self {
            uses: uses.clamp(1, MAX_INVITE_USES),
            ..Self::new(org, relay, expires_ms)
        }
    }

    /// A fresh invite for the issuer's own additional device (ADR 0011).
    pub fn new_own_device(org: DeviceId, relay: &str, expires_ms: u64, issuer: DeviceId) -> Self {
        Self {
            own_device: Some(issuer),
            ..Self::new(org, relay, expires_ms)
        }
    }

    /// `kith://invite/v1?org=…&relay=…&token=…&secret=…&expires=…`
    pub fn to_link(&self) -> String {
        format!(
            "{LINK_PREFIX}org={}&relay={}&token={}&secret={}&expires={}{}{}",
            self.org.to_hex(),
            percent_encode(&self.relay),
            hex::encode(self.token),
            hex::encode(self.secret),
            self.expires_ms,
            if self.uses == 1 {
                String::new()
            } else {
                format!("&uses={}", self.uses)
            },
            self.own_device
                .map(|d| format!("&own={}", d.to_hex()))
                .unwrap_or_default()
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
        let mut uses = 1;
        let mut own_device = None;
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
                "uses" => {
                    uses = v
                        .parse::<u32>()
                        .ok()
                        .filter(|n| (1..=MAX_INVITE_USES).contains(n))
                        .ok_or(MembershipError::Malformed("uses"))?
                }
                "own" => {
                    own_device =
                        Some(DeviceId::from_hex(v).map_err(|_| MembershipError::Malformed("own"))?)
                }
                _ => {} // ignore unknown keys from newer versions
            }
        }
        Ok(Self {
            org: org.ok_or(MembershipError::Malformed("org"))?,
            relay: relay.ok_or(MembershipError::Malformed("relay"))?,
            token: token.ok_or(MembershipError::Malformed("token"))?,
            secret: secret.ok_or(MembershipError::Malformed("secret"))?,
            expires_ms: expires.ok_or(MembershipError::Malformed("expires"))?,
            // An own-device invite links one device of its issuer: always single use.
            uses: if own_device.is_some() { 1 } else { uses },
            own_device,
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
        self.mac(b"kith/invite-claim/v1\0", key_package, &[])
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
    ///
    /// `nonce` is the admin's random answer to the claim ([`Self::nonce_signed_bytes`]).
    /// The claimer commits to its KeyPackage before the nonce exists, so someone who
    /// has the link and sees another device's claim cannot search for a KeyPackage
    /// of its own with the same code (one chance in a million per claim).
    pub fn short_code(&self, key_package: &[u8], nonce: &[u8; 32]) -> String {
        let m = self.mac(b"kith/invite-code/v2\0", key_package, nonce);
        let [a, b, c, d, ..] = m;
        let n = u32::from_be_bytes([a, b, c, d]) % 1_000_000;
        format!("{n:06}")
    }

    /// What the admin signs when it answers a claim with `nonce`: the org, the
    /// invite, the claimed KeyPackage and the nonce. The claimer checks it, so only
    /// an admin (or, for an own-device invite, its issuer) can choose the nonce.
    pub fn nonce_signed_bytes(&self, key_package: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
        const DOMAIN: &[u8] = b"kith/invite-nonce/v1\0";
        let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 32 + 32);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(self.org.as_bytes());
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&Sha256::digest(key_package));
        out.extend_from_slice(nonce);
        out
    }

    fn mac(&self, domain: &[u8], key_package: &[u8], extra: &[u8]) -> [u8; 32] {
        let mut msg = Vec::with_capacity(domain.len() + 16 + 32 + extra.len());
        msg.extend_from_slice(domain);
        msg.extend_from_slice(&self.token);
        msg.extend_from_slice(&Sha256::digest(key_package));
        msg.extend_from_slice(extra);
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
mod tests;
