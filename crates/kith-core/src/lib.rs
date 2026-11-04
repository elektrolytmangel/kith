//! Core data model for kith.
//!
//! Every object is a chain of signed, hash-linked [`Change`]s (see
//! `docs/design/0001-local-first-e2ee-sync.md`, section "Data model").
//! This crate is pure logic: no I/O, no networking, no storage. It compiles
//! for native targets and `wasm32-unknown-unknown`.

mod change;
mod ids;

pub use change::{Change, ChangeError, Signer, UnsignedChange, verify_signature};
pub use ids::{ChangeId, DeviceId, IdError, ObjectId, ObjectType};

/// `N` bytes from the operating system's secure random number generator
/// (`crypto.getRandomValues` on the web). The only randomness source in kith.
///
/// # Panics
/// If the OS has no random number generator. Continuing without one would
/// produce guessable keys.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("OS random number generator unavailable");
    b
}

/// Version of this crate, exposed to bindings so apps can report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
