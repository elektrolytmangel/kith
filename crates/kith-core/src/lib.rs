//! Core data model for kith.
//!
//! Every object is a chain of signed, hash-linked [`Change`]s (see
//! `docs/design/0001-local-first-e2ee-sync.md`, section "Data model").
//! This crate is pure logic: no I/O, no networking, no storage. It compiles
//! for native targets and `wasm32-unknown-unknown`.

mod change;
mod ids;

pub use change::{Change, ChangeError, Signer, UnsignedChange};
pub use ids::{ChangeId, DeviceId, IdError, ObjectId, ObjectType};

/// Version of this crate, exposed to bindings so apps can report it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
