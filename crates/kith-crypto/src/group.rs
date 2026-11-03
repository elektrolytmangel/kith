//! Group encryption interface (one MLS group per organization or
//! read-restricted subgroup).
//!
//! The rest of the system depends only on this trait so the MLS
//! implementation can be swapped or mocked in tests.

/// MLS epoch number.
pub type Epoch = u64;

/// Errors from group operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    /// A commit arrived for an epoch we cannot apply yet (missed commits).
    #[error("missing commits: local epoch {local}, commit for {got}")]
    EpochGap {
        /// Our epoch.
        local: Epoch,
        /// Epoch the commit applies to.
        got: Epoch,
    },
    /// Decryption or authentication failed.
    #[error("decryption failed")]
    Decrypt,
    /// Backend-specific error.
    #[error("{0}")]
    Other(String),
}

/// Operations every group encryption backend must support.
pub trait GroupCrypto {
    /// Current epoch.
    fn epoch(&self) -> Epoch;
    /// Encrypt an application message (a signed change) for the group.
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, GroupError>;
    /// Decrypt an application message.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, GroupError>;
    /// Apply a commit (add/remove/update). Commits must be applied in order.
    fn apply_commit(&mut self, commit: &[u8]) -> Result<Epoch, GroupError>;
    /// Rotate our own leaf key (MLS update). Returns the commit to broadcast.
    fn self_update(&mut self) -> Result<Vec<u8>, GroupError>;
}
