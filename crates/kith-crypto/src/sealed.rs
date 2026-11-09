//! Secrets the client keeps in its store, encrypted (ADR 0021).
//!
//! The org state (it can hold the org root key) and the MLS group state are sealed
//! with XChaCha20-Poly1305 before they reach the store. The key is derived from the
//! device key ([`storage_key`]), so a copy of the store alone (a SQLite file, an
//! IndexedDB dump, a backup of the app's data) holds no usable secret. Whoever can
//! use the device key can still read them.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use kith_core::Signer;
use sha2::{Digest, Sha256};

/// Prefix of every sealed value (format marker, ADR 0012).
pub const SEALED_MAGIC: &[u8] = b"kith/sealed/v1\0";

const KEY_TAG: &[u8] = b"kith/storage-key/v1\0";
const NONCE_LEN: usize = 24;

/// Sealing errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    /// The value is not sealed (written by an older version).
    #[error("stored state is not encrypted (written by an older version)")]
    NotSealed,
    /// The value does not decrypt: another device key, or damaged.
    #[error("stored state does not decrypt (another device key, or damaged)")]
    Decrypt,
    /// The signer's signatures are not deterministic, so no stable key exists.
    #[error("the device signer must sign deterministically (RFC 8032)")]
    Nondeterministic,
}

/// The key that seals this device's stored secrets. It is derived from an Ed25519
/// signature over a fixed, domain-separated message: Ed25519 signatures are
/// deterministic (RFC 8032), so the result is stable, and only the key holder can
/// compute it. Works with any [`Signer`], also one that never reveals its secret.
pub fn storage_key(signer: &dyn Signer) -> Result<[u8; 32], SealError> {
    let mut msg = KEY_TAG.to_vec();
    msg.extend_from_slice(&signer.device_id().0);
    let sig = signer.sign(&msg);
    if signer.sign(&msg) != sig {
        return Err(SealError::Nondeterministic);
    }
    let mut h = Sha256::new();
    h.update(KEY_TAG);
    h.update(sig);
    Ok(h.finalize().into())
}

fn aad(label: &str) -> Vec<u8> {
    let mut a = SEALED_MAGIC.to_vec();
    a.extend_from_slice(label.as_bytes());
    a
}

/// Encrypt `plain`, bound to `label` (the store slot it is written to).
#[allow(
    clippy::expect_used,
    reason = "XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail"
)]
pub fn seal(key: &[u8; 32], label: &str, plain: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = kith_core::random_bytes();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plain,
                aad: &aad(label),
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory data");
    let mut out = Vec::with_capacity(SEALED_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a value written by [`seal`] with the same `key` and `label`.
pub fn open(key: &[u8; 32], label: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    let rest = sealed
        .strip_prefix(SEALED_MAGIC)
        .ok_or(SealError::NotSealed)?;
    if rest.len() < NONCE_LEN {
        return Err(SealError::Decrypt);
    }
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| SealError::Decrypt)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad: &aad(label),
            },
        )
        .map_err(|_| SealError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKey;

    /// req: REQ-STORE-003
    #[test]
    fn sealed_values_open_only_with_the_same_device_and_slot() {
        let a = DeviceKey::generate();
        let key = storage_key(&a).unwrap();
        assert_eq!(key, storage_key(&a).unwrap(), "stable");
        let secret = b"root key and group secrets";
        let sealed = seal(&key, "orgs", secret);
        assert!(sealed.starts_with(SEALED_MAGIC));
        assert!(
            !sealed.windows(secret.len()).any(|w| w == secret),
            "no plaintext in the stored bytes"
        );
        assert_eq!(open(&key, "orgs", &sealed).unwrap(), secret);
        assert_eq!(open(&key, "mls", &sealed), Err(SealError::Decrypt));
        let other = storage_key(&DeviceKey::generate()).unwrap();
        assert_eq!(open(&other, "orgs", &sealed), Err(SealError::Decrypt));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, "orgs", &tampered), Err(SealError::Decrypt));
        assert_eq!(open(&key, "orgs", secret), Err(SealError::NotSealed));
        assert_eq!(
            open(&key, "orgs", &sealed[..SEALED_MAGIC.len() + 3]),
            Err(SealError::Decrypt)
        );
    }

    /// req: REQ-STORE-003
    #[test]
    fn a_randomized_signer_gives_no_storage_key() {
        struct Randomized(DeviceKey);
        impl Signer for Randomized {
            fn device_id(&self) -> kith_core::DeviceId {
                self.0.device_id()
            }
            fn sign(&self, _: &[u8]) -> [u8; 64] {
                let mut s = [0u8; 64];
                s[..32].copy_from_slice(&kith_core::random_bytes::<32>());
                s
            }
        }
        assert_eq!(
            storage_key(&Randomized(DeviceKey::generate())),
            Err(SealError::Nondeterministic)
        );
    }
}
