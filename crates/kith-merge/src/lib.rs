//! Deterministic merging of concurrent changes (REQ-DATA-004).
//!
//! The core never interprets payloads (REQ-DATA-002). A [`Merger`] is the
//! per-type piece that does: it turns the full change history of an object,
//! including forks created by concurrent edits, into one state. Every client
//! that holds the same set of changes must compute the same state.
//!
//! - [`automerge_merger`] (feature `automerge`, on by default): payloads are
//!   Automerge changes; the state is an Automerge document. This is the default
//!   for JSON-like application data. Changes are checked before they are applied
//!   (ADR 0020).
//! - Other types implement [`Merger`] themselves (last-writer-wins registers,
//!   detect-and-resolve, ...), or have no merger and stay forked until the
//!   app resolves them.
//!
//! Permission checks are not done here: validate changes before they reach
//! the merge (design doc, "Permissions").

use kith_core::{Change, ChangeId};

#[cfg(feature = "automerge")]
pub mod automerge_merger;

/// Errors from merging.
#[derive(Debug, thiserror::Error)]
pub enum MergeError {
    /// The merge backend failed on data that should have been valid.
    #[error("merge failed: {0}")]
    Backend(String),
}

/// The merged state of an object plus the changes that could not be used.
#[derive(Debug)]
pub struct Materialized<S> {
    /// The merged state.
    pub state: S,
    /// Changes whose payload this merger could not decode or apply. They stay in
    /// the history (it is append-only) but do not contribute to the state, so one
    /// bad change from a device cannot make the whole object unreadable.
    pub skipped: Vec<ChangeId>,
}

/// Per-type merge strategy.
pub trait Merger {
    /// The merged, application-visible state.
    type State;

    /// Merge `history` (an object's changes in arrival order, as returned by
    /// `Store::history`) into one state. Must not depend on the order of
    /// `history`: all clients converge on the same state for the same set.
    fn materialize(&self, history: &[Change]) -> Result<Materialized<Self::State>, MergeError>;
}
