//! Device keys and group encryption.
//!
//! - [`DeviceKey`]: Ed25519 key created on first launch; its public key is
//!   the device ID and it signs every change.
//! - [`group`]: MLS (RFC 9420) group encryption with OpenMLS, one group per
//!   organization ([`Groups`]); see ADR 0004.

use ed25519_dalek::{Signer as _, SigningKey};
use kith_core::{DeviceId, Signer};

pub mod files;
pub mod group;

pub use group::{Added, CommitOutcome, Decrypted, Epoch, GroupError, Groups, WelcomeInfo};

/// A device's long-term signing key.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Generate a fresh key from the OS random number generator.
    pub fn generate() -> Self {
        // An Ed25519 secret key is 32 uniformly random bytes (RFC 8032 §5.1.5).
        Self(SigningKey::from_bytes(&kith_core::random_bytes()))
    }

    /// Restore from the 32-byte secret seed (e.g. loaded from the OS keychain).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Secret seed for persisting in secure storage. Never send it anywhere.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Signer for DeviceKey {
    fn device_id(&self) -> DeviceId {
        DeviceId(self.0.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_tuple("DeviceKey").field(&self.device_id()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// req: REQ-ID-001
    #[test]
    fn device_id_is_public_key_and_survives_restore() {
        let k = DeviceKey::generate();
        let restored = DeviceKey::from_secret_bytes(&k.secret_bytes());
        assert_eq!(k.device_id(), restored.device_id());
    }

    /// RFC 8032 §7.1 TEST 1: the seed → public key → signature mapping must
    /// never change across dependency upgrades, or existing device IDs and
    /// signed history would stop verifying.
    #[test]
    fn rfc8032_test_vector_1() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let k = DeviceKey::from_secret_bytes(&seed);
        assert_eq!(
            hex::encode(k.device_id().0),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(k.sign(b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        assert_ne!(
            DeviceKey::generate().secret_bytes(),
            DeviceKey::generate().secret_bytes()
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let k = DeviceKey::generate();
        let s = format!("{k:?}");
        assert!(!s.contains(&hex_secret(&k)));
    }

    fn hex_secret(k: &DeviceKey) -> String {
        k.secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
