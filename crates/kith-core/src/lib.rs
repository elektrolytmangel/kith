//! Core data model for kith.
//!
//! Every object is a chain of signed, hash-linked [`Change`]s (see
//! `docs/design/0001-local-first-e2ee-sync.md`, section "Data model").
//! This crate is pure logic: no I/O, no networking, no storage. It compiles
//! for native targets and `wasm32-unknown-unknown`.

mod change;
mod ids;
pub mod membership;
pub mod policy;
pub mod snapshot;

pub use change::{Change, ChangeError, Signer, UnsignedChange, verify_signature};
pub use ids::{ChangeId, DeviceId, IdError, ObjectId, ObjectType, Scope, ScopeError};

/// `N` bytes from the operating system's secure random number generator
/// (`crypto.getRandomValues` on the web). The only randomness source in kith.
///
/// # Panics
/// If the OS has no random number generator. Continuing without one would
/// produce guessable keys.
#[allow(
    clippy::expect_used,
    reason = "documented: no OS randomness means no safe keys, so stopping is the only safe choice"
)]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS random number generator unavailable");
    b
}

/// `N` bytes of `bytes` starting at `at`, or `None` if they are not all there.
pub(crate) fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    <[u8; N]>::try_from(bytes.get(at..at.checked_add(N)?)?).ok()
}

/// Version of this crate, exposed to bindings so apps can report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
