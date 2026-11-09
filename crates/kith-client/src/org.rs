//! Organizations, membership certificates and invitations (phase 5, ADR 0005).
//!
//! Per org a device keeps its certificate chain (its proof of membership for the
//! relay), the root key if it created the org, and the invites it issued. All of it
//! is saved in the store's meta slot [`ORGS_KEY`] next to the MLS state.

use std::collections::BTreeMap;

use kith_core::membership::{CertChain, Invite};

/// Meta key of the saved org state (`Store::put_meta`). Contains the root key and
/// invite secrets: store it like the device key.
pub const ORGS_KEY: &str = "orgs";

/// What a device knows about one org.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrgState {
    /// Our membership proof, once we are a member.
    pub chain: Option<CertChain>,
    /// The org root key's secret, if we created the org.
    pub root: Option<[u8; 32]>,
    /// Invites we issued and that were not used yet.
    pub invites: Vec<Invite>,
}

impl Drop for OrgState {
    fn drop(&mut self) {
        if let Some(root) = &mut self.root {
            zeroize::Zeroize::zeroize(root);
        }
    }
}

/// All orgs, saved as one blob.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Orgs(pub BTreeMap<String, OrgState>);

/// Why a saved org state could not be read. The wording shows up in
/// `ClientError::StoredState`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OrgStateError {
    /// The blob does not start with the format marker.
    #[error("unknown org state format")]
    UnknownFormat,
    /// The blob ends in the middle of a field.
    #[error("truncated org state")]
    Truncated,
    /// A count larger than the data that follows.
    #[error("count exceeds data")]
    CountExceedsData,
    /// A string field that is not UTF-8.
    #[error("not UTF-8")]
    NotUtf8,
    /// The root-key flag is neither 0 nor 1.
    #[error("root flag")]
    RootFlag,
    /// Bytes after the last org.
    #[error("trailing bytes")]
    TrailingBytes,
    /// A saved certificate chain or invite link that does not parse.
    #[error("{0}")]
    Invalid(String),
}

const MAGIC: &[u8] = b"kith/orgs/v1\0";

impl Orgs {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = MAGIC.to_vec();
        put_u32(&mut w, self.0.len());
        for (org, st) in &self.0 {
            put_bytes(&mut w, org.as_bytes());
            put_bytes(
                &mut w,
                st.chain
                    .as_ref()
                    .map(CertChain::to_hex)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            match &st.root {
                Some(r) => {
                    w.push(1);
                    w.extend_from_slice(r);
                }
                None => w.push(0),
            }
            put_u32(&mut w, st.invites.len());
            for inv in &st.invites {
                put_bytes(&mut w, inv.to_link().as_bytes());
            }
        }
        w
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, OrgStateError> {
        let mut r = Reader(b);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(OrgStateError::UnknownFormat);
        }
        let mut orgs = BTreeMap::new();
        for _ in 0..r.count()? {
            let org = r.string()?;
            let chain = match r.string()? {
                s if s.is_empty() => None,
                s => Some(
                    CertChain::from_hex(&s).map_err(|e| OrgStateError::Invalid(e.to_string()))?,
                ),
            };
            let root = match r.take(1)?[0] {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(OrgStateError::RootFlag),
            };
            let mut invites = vec![];
            for _ in 0..r.count()? {
                invites.push(
                    Invite::parse(&r.string()?)
                        .map_err(|e| OrgStateError::Invalid(e.to_string()))?,
                );
            }
            orgs.insert(
                org,
                OrgState {
                    chain,
                    root,
                    invites,
                },
            );
        }
        if !r.0.is_empty() {
            return Err(OrgStateError::TrailingBytes);
        }
        Ok(Self(orgs))
    }
}

fn put_u32(w: &mut Vec<u8>, n: usize) {
    w.extend_from_slice(&(n as u32).to_be_bytes());
}

fn put_bytes(w: &mut Vec<u8>, b: &[u8]) {
    put_u32(w, b.len());
    w.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], OrgStateError> {
        if self.0.len() < n {
            return Err(OrgStateError::Truncated);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }

    /// The next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], OrgStateError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| OrgStateError::Truncated)
    }

    fn count(&mut self) -> Result<usize, OrgStateError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        if n > self.0.len() / 4 {
            return Err(OrgStateError::CountExceedsData);
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, OrgStateError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| OrgStateError::NotUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::Signer;
    use kith_core::membership::MembershipCert;
    use kith_crypto::DeviceKey;

    #[test]
    fn org_state_roundtrips_and_rejects_garbage() {
        let (root, dev) = (DeviceKey::generate(), DeviceKey::generate());
        let org = root.device_id();
        let mut orgs = Orgs::default();
        orgs.0.insert(
            org.to_hex(),
            OrgState {
                chain: Some(CertChain(vec![MembershipCert::issue(
                    &root,
                    org,
                    dev.device_id(),
                    true,
                    5,
                )])),
                root: Some(root.secret_bytes()),
                invites: vec![Invite::new(org, "ws://r/v1/ws", 9)],
            },
        );
        orgs.0.insert("other".into(), OrgState::default());
        let bytes = orgs.to_bytes();
        assert_eq!(Orgs::from_bytes(&bytes).unwrap(), orgs);
        for len in [0, 3, bytes.len() / 2, bytes.len() - 1] {
            assert!(Orgs::from_bytes(&bytes[..len]).is_err(), "len {len}");
        }
    }

    /// The wording is shown in `ClientError::StoredState`: keep it.
    #[test]
    fn org_state_errors_keep_their_wording() {
        let err = |b: &[u8]| Orgs::from_bytes(b).unwrap_err().to_string();
        let with = |rest: &[u8]| [MAGIC, rest].concat();
        assert_eq!(err(&[]), "truncated org state");
        assert_eq!(err(&[0; 13]), "unknown org state format");
        assert_eq!(err(&with(&[0, 0, 0, 9])), "count exceeds data");
        assert_eq!(err(&with(&[0, 0, 0, 1, 0, 0, 0, 1, 0xff])), "not UTF-8");
        // One org "a", empty chain, then a root flag that is neither 0 nor 1.
        assert_eq!(
            err(&with(&[0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 2])),
            "root flag"
        );
        let mut ok = with(&[0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(Orgs::from_bytes(&ok).is_ok());
        ok.push(0);
        assert_eq!(err(&ok), "trailing bytes");
        // A chain that is not a certificate chain.
        assert!(
            !err(&with(&[
                0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0, 2, b'z', b'z', 0, 0, 0, 0, 0
            ]))
            .is_empty()
        );
    }

    /// Every prefix and single-byte corruption of a saved state is read or refused.
    #[test]
    fn org_state_survives_truncation_and_corruption() {
        let key = DeviceKey::generate();
        let org = key.device_id();
        let mut orgs = Orgs::default();
        orgs.0.insert(
            org.to_hex(),
            OrgState {
                chain: None,
                root: Some(key.secret_bytes()),
                invites: vec![Invite::new(org, "ws://r/v1/ws", 9)],
            },
        );
        let bytes = orgs.to_bytes();
        for n in 0..=bytes.len() {
            let _ = Orgs::from_bytes(&bytes[..n]);
        }
        for i in 0..bytes.len() {
            for flip in [0xffu8, 0x01, 0x80] {
                let mut b = bytes.clone();
                b[i] ^= flip;
                let _ = Orgs::from_bytes(&b);
            }
        }
    }
}
