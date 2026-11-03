//! Device keys and group encryption.
//!
//! - [`DeviceKey`]: Ed25519 key created on first launch; its public key is
//!   the device ID and it signs every change.
//! - [`group`]: the MLS (RFC 9420) abstraction. Implemented with OpenMLS in
//!   phase 4 (see `docs/requirements/encryption.md`).

use ed25519_dalek::{Signer as _, SigningKey};
use kith_core::{DeviceId, Signer};

pub mod group;

/// A device's long-term signing key.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Generate a fresh key from the OS RNG.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand_core::OsRng))
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
