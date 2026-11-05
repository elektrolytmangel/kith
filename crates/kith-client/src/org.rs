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

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let mut r = Reader(b);
        if r.take(MAGIC.len())? != MAGIC {
            return Err("unknown org state format".into());
        }
        let mut orgs = BTreeMap::new();
        for _ in 0..r.count()? {
            let org = r.string()?;
            let chain = match r.string()? {
                s if s.is_empty() => None,
                s => Some(CertChain::from_hex(&s).map_err(|e| e.to_string())?),
            };
            let root = match r.take(1)?[0] {
                0 => None,
                1 => Some(r.take(32)?.try_into().expect("32 bytes")),
                _ => return Err("root flag".into()),
            };
            let mut invites = vec![];
            for _ in 0..r.count()? {
                invites.push(Invite::parse(&r.string()?).map_err(|e| e.to_string())?);
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
            return Err("trailing bytes".into());
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated org state".into());
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn count(&mut self) -> Result<usize, String> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        if n > self.0.len() / 4 {
            return Err("count exceeds data".into());
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<String, String> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "not UTF-8".into())
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
}
