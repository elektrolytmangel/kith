//! Automerge-backed [`Merger`]: a change's payload is one Automerge change
//! (the bytes of `automerge::Change`), the state is an [`AutoCommit`] document.

use automerge::transaction::Transactable;
use automerge::{AutoCommit, AutomergeError};
use kith_core::Change;

use crate::{Materialized, MergeError, Merger};

pub use automerge;

/// Merges objects whose payloads are Automerge changes.
#[derive(Clone, Copy, Debug, Default)]
pub struct AutomergeMerger;

impl Merger for AutomergeMerger {
    type State = AutoCommit;

    fn materialize(&self, history: &[Change]) -> Result<Materialized<AutoCommit>, MergeError> {
        let mut doc = AutoCommit::new();
        let mut skipped = Vec::new();
        let mut changes = Vec::with_capacity(history.len());
        for c in history {
            match automerge::Change::from_bytes(c.body.payload.clone()) {
                Ok(ac) => changes.push((c.change_id, ac)),
                Err(_) => skipped.push(c.change_id),
            }
        }
        // Automerge queues changes whose dependencies have not arrived yet and applies
        // duplicates once, so neither arrival order nor repetition matters.
        doc.apply_changes(changes.into_iter().map(|(_, ac)| ac))
            .map_err(|e| MergeError::Backend(e.to_string()))?;
        Ok(Materialized {
            state: doc,
            skipped,
        })
    }
}

/// Run `edit` on `doc` and return the resulting change as a payload for
/// `Client::create` / `Client::edit`, or `None` if `edit` changed nothing.
pub fn author(
    doc: &mut AutoCommit,
    edit: impl FnOnce(&mut AutoCommit) -> Result<(), AutomergeError>,
) -> Result<Option<Vec<u8>>, MergeError> {
    let before = doc.get_heads();
    edit(doc).map_err(|e| MergeError::Backend(e.to_string()))?;
    doc.commit();
    if doc.get_heads() == before {
        return Ok(None);
    }
    Ok(doc.get_last_local_change().map(|c| c.raw_bytes().to_vec()))
}

/// Convenience: set a string value in the document root.
pub fn put_str(doc: &mut AutoCommit, key: &str, value: &str) -> Result<(), AutomergeError> {
    doc.put(automerge::ROOT, key, value)
}
