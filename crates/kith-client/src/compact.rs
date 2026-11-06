//! History compaction (REQ-DATA-005, ADR 0026).
//!
//! An admin folds old changes of an object into a **snapshot**: a signed change that
//! names the changes it covers (and, for documents, carries their payloads). Every
//! device that accepts it deletes the covered changes and keeps only their IDs, so
//! sync never asks for them again. What may be folded is set per object type in the
//! policy ([`Retention`]); the default keeps everything.

use std::collections::{BTreeSet, HashMap, HashSet};

use kith_core::snapshot::{self, Snapshot};

use crate::files::{FILE_TYPE, FileRef};
use crate::*;

/// Fewest changes a snapshot made by [`Client::compact`] folds, so that a snapshot is
/// only made when it saves something.
pub const COMPACT_MIN_CHANGES: usize = 100;

/// Most snapshots one call creates per object.
const MAX_SNAPSHOTS_PER_OBJECT: usize = 20;

impl<S: Store, K: Signer> Client<S, K> {
    /// Set how much history objects of `object_type` keep in `org` (admins only).
    /// Nothing is folded until an admin calls [`Self::compact`]. Broadcast the
    /// returned change like any other.
    pub fn set_retention(
        &mut self,
        org: &str,
        object_type: &str,
        retention: Retention,
    ) -> Result<Change, ClientError> {
        self.policy_commit(
            org,
            PolicyOp::SetRetention {
                object_type: object_type.into(),
                retention,
            },
        )
    }

    /// Fold old history into snapshots, as the org's retention rules allow (admins
    /// only). Send the returned frames; this device has already deleted what it folded.
    pub fn compact(&mut self, org: &str) -> Result<Vec<Frame>, ClientError> {
        self.compact_min(org, COMPACT_MIN_CHANGES)
    }

    /// [`Self::compact`] with a different minimum: make a snapshot as soon as it
    /// would fold `min_changes` changes.
    pub fn compact_min(
        &mut self,
        org: &str,
        min_changes: usize,
    ) -> Result<Vec<Frame>, ClientError> {
        if !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        let rules = match self.policies.get(org) {
            Some(p) if p.creator.is_some() => p.retention.clone(),
            _ => return Ok(vec![]),
        };
        let mut frames = vec![];
        for creation in self.objects(None)? {
            let scope = creation.body.scope.clone();
            let ty = creation.body.object_type.as_str();
            let rule = rules.get(ty).copied().unwrap_or_default();
            // Only objects of this org whose group we are in can be written.
            if rule == Retention::KeepAll
                || !in_org(org, scope.as_str())
                || !self.groups.is_member(scope.as_str())
            {
                continue;
            }
            for _ in 0..MAX_SNAPSHOTS_PER_OBJECT {
                let Some(snap) =
                    self.snapshot_object(&creation.body.object_id, rule, min_changes)?
                else {
                    break;
                };
                frames.push(self.broadcast_frame(org, &snap)?);
            }
        }
        self.save_groups()?;
        Ok(frames)
    }

    /// Create (and apply) one snapshot of `object`, or `None` if the rule lets nothing
    /// go or less than `min` changes.
    fn snapshot_object(
        &mut self,
        object: &ObjectId,
        rule: Retention,
        min: usize,
    ) -> Result<Option<Change>, ClientError> {
        let all = self.merge_history(object)?;
        let changes: Vec<&Change> = all
            .iter()
            .filter(|c| !snapshot::is_snapshot(&c.body.payload))
            .collect();
        let is_doc = changes.iter().any(|c| is_document_change(&c.body.payload))
            || all
                .iter()
                .any(|c| Snapshot::decode(&c.body.payload).is_some_and(|s| !s.bundle.is_empty()));
        let order = topological(&changes);
        // The changes the rule lets go: a prefix of the causal order, or the old ones
        // plus everything they build on.
        let mut take: HashSet<ChangeId> = match rule {
            Retention::KeepAll => HashSet::new(),
            Retention::KeepLast(n) => order
                .iter()
                .take(order.len().saturating_sub(n as usize))
                .map(|c| c.change_id)
                .collect(),
            Retention::KeepDays(days) => {
                let cutoff = now_ms().saturating_sub(u64::from(days) * 86_400_000);
                let old: Vec<ChangeId> = order
                    .iter()
                    .filter(|c| c.body.timestamp_ms < cutoff)
                    .map(|c| c.change_id)
                    .collect();
                close_over_parents(&changes, old)
            }
        };
        if !is_doc {
            // A raw object has no merged state: what is left is what the app reads, so
            // the newest changes (the heads) stay.
            let named: HashSet<ChangeId> = changes
                .iter()
                .flat_map(|c| c.body.parents.iter().copied())
                .collect();
            take.retain(|id| named.contains(id));
        }
        let mut chosen: Vec<&Change> = vec![];
        let mut size = snapshot::MAGIC.len() + 8;
        for c in order.iter().filter(|c| take.contains(&c.change_id)) {
            let bundled = is_doc && is_document_change(&c.body.payload);
            let add = 32 + if bundled { 4 + c.body.payload.len() } else { 0 };
            if chosen.len() >= snapshot::MAX_COVERS || size + add > snapshot::MAX_ENCODED {
                break;
            }
            size += add;
            chosen.push(c);
        }
        if chosen.is_empty() || chosen.len() < min {
            return Ok(None);
        }
        let ids: HashSet<ChangeId> = chosen.iter().map(|c| c.change_id).collect();
        let snap = Snapshot {
            covers: chosen.iter().map(|c| c.change_id).collect(),
            bundle: chosen
                .iter()
                .filter(|c| is_doc && is_document_change(&c.body.payload))
                .map(|c| c.body.payload.clone())
                .collect(),
        };
        // It sits after what it folded, not after what it leaves.
        let named: HashSet<ChangeId> = chosen
            .iter()
            .flat_map(|c| c.body.parents.iter().copied())
            .collect();
        let mut parents: Vec<ChangeId> =
            ids.iter().filter(|i| !named.contains(i)).copied().collect();
        parents.sort();
        let (ty, scope) = self.object_meta(object)?;
        let change = self.commit(scope, *object, ty, parents, snap.encode())?;
        self.apply_snapshot(&change)?;
        Ok(Some(change))
    }

    /// Apply an accepted snapshot: remember what it covers and delete those changes
    /// (creation changes stay, they list the object). A snapshot counts if an admin
    /// made it and the policy does not reject it.
    pub(crate) fn apply_snapshot(&mut self, change: &Change) -> Result<(), ClientError> {
        let Some(org) = change.body.scope.org_id().map(|o| o.to_hex()) else {
            return Ok(());
        };
        let known = self.policies.get(&org).is_some_and(|p| p.creator.is_some());
        if !known || self.invalid.contains(&change.change_id) {
            // Without the policy we can't tell who is an admin; it is applied when the
            // policy arrives (`refresh_policies`).
            return Ok(());
        }
        let Some(snap) = Snapshot::decode(&change.body.payload) else {
            return Ok(());
        };
        let (mut gone, mut kept_creations) = (vec![], vec![]);
        for id in &snap.covers {
            self.covered.insert(*id);
            if let Some(c) = self.store.get(id)? {
                if c.is_creation() {
                    kept_creations.push(c);
                } else {
                    gone.push(c);
                }
            }
        }
        self.prune(gone, kept_creations)
    }

    /// Delete changes a snapshot covers, and the file chunks only they used. The
    /// covered creation changes stay stored but no longer keep chunks alive.
    fn prune(&mut self, gone: Vec<Change>, creations: Vec<Change>) -> Result<(), ClientError> {
        if gone.is_empty() && creations.is_empty() {
            return Ok(());
        }
        let mut candidates: HashSet<[u8; 32]> = HashSet::new();
        let mut file_objects = BTreeSet::new();
        for c in gone.iter().chain(&creations) {
            if c.body.object_type.as_str() == FILE_TYPE
                && let Some(r) = FileRef::decode(&c.body.payload)
            {
                candidates.extend(r.chunks);
                file_objects.insert(c.body.object_id);
            }
        }
        let ids: Vec<ChangeId> = gone.iter().map(|c| c.change_id).collect();
        self.store.delete(&ids)?;
        if candidates.is_empty() {
            return Ok(());
        }
        // Chunks the versions we keep still use stay.
        for object in file_objects {
            for c in self.store.history(&object)? {
                if self.covered.contains(&c.change_id) {
                    continue;
                }
                if let Some(r) = FileRef::decode(&c.body.payload) {
                    for chunk in r.chunks {
                        candidates.remove(&chunk);
                    }
                }
            }
        }
        for chunk in candidates {
            self.store.delete_chunk(&chunk)?;
        }
        Ok(())
    }
}

#[cfg(feature = "automerge")]
fn is_document_change(payload: &[u8]) -> bool {
    automerge_merger::is_change(payload)
}

#[cfg(not(feature = "automerge"))]
fn is_document_change(_payload: &[u8]) -> bool {
    false
}

/// `changes` in causal order (parents first), ties by time and ID, so every device
/// that holds the same changes gets the same order.
fn topological<'a>(changes: &[&'a Change]) -> Vec<&'a Change> {
    let by_id: HashMap<ChangeId, &Change> = changes.iter().map(|c| (c.change_id, *c)).collect();
    let mut waiting: HashMap<ChangeId, usize> = HashMap::new();
    let mut children: HashMap<ChangeId, Vec<ChangeId>> = HashMap::new();
    let mut ready: BTreeSet<(u64, ChangeId)> = BTreeSet::new();
    for c in changes {
        let parents: HashSet<&ChangeId> = c
            .body
            .parents
            .iter()
            .filter(|p| by_id.contains_key(*p))
            .collect();
        if parents.is_empty() {
            ready.insert((c.body.timestamp_ms, c.change_id));
        } else {
            waiting.insert(c.change_id, parents.len());
            for p in parents {
                children.entry(*p).or_default().push(c.change_id);
            }
        }
    }
    let mut out = Vec::with_capacity(changes.len());
    while let Some((_, id)) = ready.pop_first() {
        out.push(by_id[&id]);
        for child in children.get(&id).into_iter().flatten() {
            if let Some(n) = waiting.get_mut(child) {
                *n -= 1;
                if *n == 0 {
                    waiting.remove(child);
                    ready.insert((by_id[child].body.timestamp_ms, *child));
                }
            }
        }
    }
    out
}

/// `start` plus every stored ancestor of it.
fn close_over_parents(changes: &[&Change], start: Vec<ChangeId>) -> HashSet<ChangeId> {
    let by_id: HashMap<ChangeId, &Change> = changes.iter().map(|c| (c.change_id, *c)).collect();
    let mut seen: HashSet<ChangeId> = HashSet::new();
    let mut stack = start;
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(c) = by_id.get(&id) {
            stack.extend(
                c.body
                    .parents
                    .iter()
                    .copied()
                    .filter(|p| by_id.contains_key(p)),
            );
        }
    }
    seen
}
