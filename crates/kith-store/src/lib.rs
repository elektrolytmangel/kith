//! Local storage.
//!
//! The [`Store`] trait is the seam apps can implement for their platform
//! (SQLite on native, IndexedDB on web, ...). [`MemoryStore`] is the
//! reference implementation used in tests. [`SqliteStore`] (feature
//! `sqlite`, native only) persists to disk (REQ-STORE-001).

pub mod codec;
#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::{ObjectSummary, SqliteStore};

use std::collections::{BTreeMap, HashMap};

use kith_core::{Change, ChangeId, ObjectId};

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Backend failure.
    #[error("storage backend: {0}")]
    Backend(String),
}

/// Append-only store of validated changes.
pub trait Store {
    /// Insert a validated change. Inserting an existing change is a no-op.
    fn put(&mut self, change: Change) -> Result<bool, StoreError>;
    /// Fetch one change.
    fn get(&self, id: &ChangeId) -> Result<Option<Change>, StoreError>;
    /// True if the change is stored.
    fn contains(&self, id: &ChangeId) -> Result<bool, StoreError>;
    /// All changes of an object, in arrival order.
    fn history(&self, object: &ObjectId) -> Result<Vec<Change>, StoreError>;
    /// IDs of all stored changes (input to set reconciliation).
    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError>;
    /// Current heads of an object: changes no other stored change names as
    /// parent. Sorted, so every device reports the same heads for the same set.
    fn heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, StoreError> {
        let hist = self.history(object)?;
        let mut heads: Vec<ChangeId> = hist.iter().map(|c| c.change_id).collect();
        for c in &hist {
            heads.retain(|h| !c.body.parents.contains(h));
        }
        heads.sort();
        Ok(heads)
    }
}

impl<S: Store + ?Sized> Store for Box<S> {
    fn put(&mut self, change: Change) -> Result<bool, StoreError> {
        (**self).put(change)
    }
    fn get(&self, id: &ChangeId) -> Result<Option<Change>, StoreError> {
        (**self).get(id)
    }
    fn contains(&self, id: &ChangeId) -> Result<bool, StoreError> {
        (**self).contains(id)
    }
    fn history(&self, object: &ObjectId) -> Result<Vec<Change>, StoreError> {
        (**self).history(object)
    }
    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError> {
        (**self).all_ids()
    }
    fn heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, StoreError> {
        (**self).heads(object)
    }
}

/// In-memory store, for tests and ephemeral clients.
#[derive(Default, Debug)]
pub struct MemoryStore {
    changes: HashMap<ChangeId, Change>,
    by_object: BTreeMap<ObjectId, Vec<ChangeId>>,
}

impl MemoryStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn put(&mut self, change: Change) -> Result<bool, StoreError> {
        if self.changes.contains_key(&change.change_id) {
            return Ok(false);
        }
        self.by_object
            .entry(change.body.object_id)
            .or_default()
            .push(change.change_id);
        self.changes.insert(change.change_id, change);
        Ok(true)
    }

    fn get(&self, id: &ChangeId) -> Result<Option<Change>, StoreError> {
        Ok(self.changes.get(id).cloned())
    }

    fn contains(&self, id: &ChangeId) -> Result<bool, StoreError> {
        Ok(self.changes.contains_key(id))
    }

    fn history(&self, object: &ObjectId) -> Result<Vec<Change>, StoreError> {
        Ok(self
            .by_object
            .get(object)
            .into_iter()
            .flatten()
            .filter_map(|id| self.changes.get(id).cloned())
            .collect())
    }

    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError> {
        Ok(self.changes.keys().copied().collect())
    }
}
