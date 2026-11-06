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

use kith_core::{Change, ChangeId, ObjectId, Scope};

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
    /// IDs of all stored changes.
    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError>;
    /// IDs of the stored changes in `scope` (input to set reconciliation). The
    /// default loads every change; backends should index it.
    fn scope_ids(&self, scope: &Scope) -> Result<Vec<ChangeId>, StoreError> {
        let mut out = Vec::new();
        for id in self.all_ids()? {
            if self.get(&id)?.is_some_and(|c| &c.body.scope == scope) {
                out.push(id);
            }
        }
        Ok(out)
    }
    /// Forget these changes completely (history compaction, REQ-DATA-005): after
    /// this `get`, `contains`, `history` and the ID lists no longer know them. Unknown
    /// IDs are ignored. Only the client calls it, for changes a snapshot covers.
    fn delete(&mut self, ids: &[ChangeId]) -> Result<(), StoreError>;
    /// Remove a file chunk (nothing happens if it is not stored).
    fn delete_chunk(&mut self, id: &[u8; 32]) -> Result<(), StoreError>;
    /// Store an encrypted file chunk (REQ-FILE-001) under its ID (SHA-256 of `data`),
    /// tagged with the scope of the file it belongs to.
    fn put_chunk(&mut self, id: &[u8; 32], scope: &Scope, data: &[u8]) -> Result<(), StoreError>;
    /// A stored chunk and its scope.
    fn get_chunk(&self, id: &[u8; 32]) -> Result<Option<(Scope, Vec<u8>)>, StoreError>;
    /// A small named blob kept next to the changes (e.g. `"mls"`, the MLS group
    /// state). `None` if never written.
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Replace a named blob. Must be durable when it returns, as far as the backend
    /// allows: the MLS state is saved before each encrypted message is sent, and
    /// losing it could reuse an encryption key.
    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError>;
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
    fn scope_ids(&self, scope: &Scope) -> Result<Vec<ChangeId>, StoreError> {
        (**self).scope_ids(scope)
    }
    fn heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, StoreError> {
        (**self).heads(object)
    }
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        (**self).get_meta(key)
    }
    fn delete(&mut self, ids: &[ChangeId]) -> Result<(), StoreError> {
        (**self).delete(ids)
    }
    fn delete_chunk(&mut self, id: &[u8; 32]) -> Result<(), StoreError> {
        (**self).delete_chunk(id)
    }
    fn put_chunk(&mut self, id: &[u8; 32], scope: &Scope, data: &[u8]) -> Result<(), StoreError> {
        (**self).put_chunk(id, scope, data)
    }
    fn get_chunk(&self, id: &[u8; 32]) -> Result<Option<(Scope, Vec<u8>)>, StoreError> {
        (**self).get_chunk(id)
    }
    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        (**self).put_meta(key, value)
    }
}

/// In-memory store, for tests and ephemeral clients.
#[derive(Default, Debug)]
pub struct MemoryStore {
    changes: HashMap<ChangeId, Change>,
    by_object: BTreeMap<ObjectId, Vec<ChangeId>>,
    by_scope: HashMap<Scope, Vec<ChangeId>>,
    meta: HashMap<String, Vec<u8>>,
    chunks: HashMap<[u8; 32], (Scope, Vec<u8>)>,
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
        self.by_scope
            .entry(change.body.scope.clone())
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

    fn scope_ids(&self, scope: &Scope) -> Result<Vec<ChangeId>, StoreError> {
        Ok(self.by_scope.get(scope).cloned().unwrap_or_default())
    }

    fn delete(&mut self, ids: &[ChangeId]) -> Result<(), StoreError> {
        let gone: std::collections::HashSet<&ChangeId> = ids.iter().collect();
        let mut objects = std::collections::BTreeSet::new();
        let mut scopes = std::collections::HashSet::new();
        for id in ids {
            if let Some(c) = self.changes.remove(id) {
                objects.insert(c.body.object_id);
                scopes.insert(c.body.scope);
            }
        }
        for o in objects {
            if let Some(v) = self.by_object.get_mut(&o) {
                v.retain(|id| !gone.contains(id));
            }
        }
        for sc in scopes {
            if let Some(v) = self.by_scope.get_mut(&sc) {
                v.retain(|id| !gone.contains(id));
            }
        }
        Ok(())
    }

    fn delete_chunk(&mut self, id: &[u8; 32]) -> Result<(), StoreError> {
        self.chunks.remove(id);
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.meta.get(key).cloned())
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.meta.insert(key.into(), value.to_vec());
        Ok(())
    }

    fn put_chunk(&mut self, id: &[u8; 32], scope: &Scope, data: &[u8]) -> Result<(), StoreError> {
        self.chunks.insert(*id, (scope.clone(), data.to_vec()));
        Ok(())
    }

    fn get_chunk(&self, id: &[u8; 32]) -> Result<Option<(Scope, Vec<u8>)>, StoreError> {
        Ok(self.chunks.get(id).cloned())
    }
}
