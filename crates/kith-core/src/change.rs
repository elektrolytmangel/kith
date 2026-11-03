use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ChangeId, DeviceId, ObjectId, ObjectType};

/// Something that can sign changes on behalf of a device.
///
/// Implemented by `kith_crypto::DeviceKey`; apps may provide their own
/// (for example backed by a secure enclave or hardware key).
pub trait Signer {
    /// The device ID (public key) that signatures verify against.
    fn device_id(&self) -> DeviceId;
    /// Sign `msg` with Ed25519.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// Errors when validating a change.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChangeError {
    /// `change_id` does not match the hash of the contents.
    #[error("change id does not match contents")]
    IdMismatch,
    /// Author is not a valid Ed25519 public key.
    #[error("author is not a valid public key")]
    BadAuthorKey,
    /// Signature does not verify against the author key.
    #[error("invalid signature")]
    BadSignature,
}

/// The fields of a change that the author fills in before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnsignedChange {
    /// Object this change belongs to.
    pub object_id: ObjectId,
    /// Type tag of the object.
    pub object_type: ObjectType,
    /// Change IDs this change builds on (empty for creation).
    pub parents: Vec<ChangeId>,
    /// Author's wall clock in milliseconds since the Unix epoch. Informational only.
    pub timestamp_ms: u64,
    /// Opaque bytes: a CRDT change or an application-defined operation.
    pub payload: Vec<u8>,
}

/// A signed, hash-linked change envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Change {
    /// Hash of the envelope contents.
    pub change_id: ChangeId,
    /// Signed contents.
    pub body: UnsignedChange,
    /// Author device.
    pub author: DeviceId,
    /// Ed25519 signature by `author` over the canonical encoding.
    #[cfg_attr(feature = "serde", serde(with = "sig_serde"))]
    pub signature: [u8; 64],
}

impl Change {
    /// Sign `body` with `signer`, producing a complete change.
    pub fn sign(body: UnsignedChange, signer: &dyn Signer) -> Self {
        let author = signer.device_id();
        let bytes = canonical_bytes(&body, &author);
        let change_id = ChangeId(Sha256::digest(&bytes).into());
        let signature = signer.sign(&bytes);
        Self {
            change_id,
            body,
            author,
            signature,
        }
    }

    /// Check hash and signature. Permission checks happen elsewhere
    /// (they depend on the policy object, see design section "Permissions").
    pub fn verify(&self) -> Result<(), ChangeError> {
        let bytes = canonical_bytes(&self.body, &self.author);
        if ChangeId(Sha256::digest(&bytes).into()) != self.change_id {
            return Err(ChangeError::IdMismatch);
        }
        let key = VerifyingKey::from_bytes(self.author.as_bytes())
            .map_err(|_| ChangeError::BadAuthorKey)?;
        key.verify(&bytes, &Signature::from_bytes(&self.signature))
            .map_err(|_| ChangeError::BadSignature)
    }

    /// True if this change creates its object.
    pub fn is_creation(&self) -> bool {
        self.body.parents.is_empty()
    }
}

/// Deterministic, length-prefixed encoding of everything that is signed.
///
/// Changing this breaks every existing signature: bump the domain tag.
fn canonical_bytes(c: &UnsignedChange, author: &DeviceId) -> Vec<u8> {
    const DOMAIN: &[u8] = b"kith/change/v1";
    let mut out = Vec::with_capacity(128 + c.payload.len());
    let mut put = |b: &[u8]| {
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(b);
    };
    put(DOMAIN);
    put(c.object_id.as_bytes());
    put(c.object_type.as_str().as_bytes());
    put(&(c.parents.len() as u64).to_be_bytes());
    for p in &c.parents {
        put(p.as_bytes());
    }
    put(author.as_bytes());
    put(&c.timestamp_ms.to_be_bytes());
    put(&c.payload);
    out
}

#[cfg(feature = "serde")]
mod sig_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
    }
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

    fn key(seed: u8) -> TestKey {
        TestKey(SigningKey::from_bytes(&[seed; 32]))
    }

    fn body(parents: Vec<ChangeId>) -> UnsignedChange {
        UnsignedChange {
            object_id: ObjectId([7; 16]),
            object_type: ObjectType::new("note"),
            parents,
            timestamp_ms: 1,
            payload: b"hello".to_vec(),
        }
    }

    /// req: REQ-DATA-001, REQ-DATA-003
    #[test]
    fn signed_change_verifies_and_links_parents() {
        let k = key(1);
        let first = Change::sign(body(vec![]), &k);
        let second = Change::sign(body(vec![first.change_id]), &k);
        assert!(first.is_creation());
        assert_eq!(second.body.parents, vec![first.change_id]);
        assert_eq!(first.verify(), Ok(()));
        assert_eq!(second.verify(), Ok(()));
    }

    /// req: REQ-DATA-001
    #[test]
    fn tampered_payload_is_rejected() {
        let mut c = Change::sign(body(vec![]), &key(1));
        c.body.payload = b"evil".to_vec();
        assert_eq!(c.verify(), Err(ChangeError::IdMismatch));
    }

    /// req: REQ-DATA-001
    #[test]
    fn forged_author_is_rejected() {
        let mut c = Change::sign(body(vec![]), &key(1));
        c.author = key(2).device_id();
        // Hash covers the author, so the id no longer matches.
        assert_eq!(c.verify(), Err(ChangeError::IdMismatch));
    }

    /// req: REQ-DATA-002
    #[test]
    fn payload_is_opaque_bytes() {
        let mut b = body(vec![]);
        b.payload = vec![0, 255, 1, 254];
        b.object_type = ObjectType::new("app/custom-binary");
        assert_eq!(Change::sign(b, &key(3)).verify(), Ok(()));
    }
}
