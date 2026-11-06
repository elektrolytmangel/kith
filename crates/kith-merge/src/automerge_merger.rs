//! Automerge-backed [`Merger`]: a change's payload is one Automerge change
//! (the bytes of `automerge::Change`), the state is an [`AutoCommit`] document.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;

use automerge::legacy::{ElementId, Key, ObjectId, OpId, OpType};
use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, AutomergeError, ChangeHash};
use kith_core::{Change, ChangeId};

use crate::{Materialized, MergeError, Merger};

pub use automerge;

/// Largest Automerge change accepted, in bytes after decompression.
pub const MAX_CHANGE_BYTES: u64 = 8 * 1024 * 1024;

/// Deepest nesting of objects (maps, lists, text) accepted in a document; changes
/// that nest deeper are skipped, and [`to_json`] and [`merge_patch`] stop there too.
pub const MAX_DEPTH: usize = 100;

/// Merges objects whose payloads are Automerge changes.
///
/// Changes are checked before Automerge applies them, in causal order: each
/// operation may only refer to objects, list elements and earlier operations
/// from the change's own history, and objects nest at most [`MAX_DEPTH`] deep.
/// A change that fails (and every change built on it) is skipped. The result
/// depends only on the set of changes, not their order.
#[derive(Clone, Copy, Debug, Default)]
pub struct AutomergeMerger;

impl Merger for AutomergeMerger {
    type State = AutoCommit;

    fn materialize(&self, history: &[Change]) -> Result<Materialized<AutoCommit>, MergeError> {
        let mut skipped = Vec::new();
        // One entry per Automerge change; kith changes carrying the same one share it.
        let mut parsed: HashMap<ChangeHash, (automerge::Change, Vec<ChangeId>)> = HashMap::new();
        for c in history {
            // A snapshot carries the payloads of the changes it covers (ADR 0026);
            // they go through the same checks as any other change.
            if kith_core::snapshot::is_snapshot(&c.body.payload) {
                match kith_core::snapshot::Snapshot::decode(&c.body.payload) {
                    Some(snap) => {
                        for payload in &snap.bundle {
                            if let Some(ac) = parse(payload) {
                                parsed.entry(ac.hash()).or_insert_with(|| (ac, Vec::new()));
                            }
                        }
                    }
                    None => skipped.push(c.change_id),
                }
                continue;
            }
            match parse(&c.body.payload) {
                Some(ac) => parsed
                    .entry(ac.hash())
                    .or_insert_with(|| (ac, Vec::new()))
                    .1
                    .push(c.change_id),
                None => skipped.push(c.change_id),
            }
        }
        let (good, bad) = check_in_causal_order(&parsed);
        for h in bad {
            skipped.extend(parsed[&h].1.iter().copied());
        }
        let good: Vec<automerge::Change> = good.iter().map(|h| parsed[h].0.clone()).collect();
        let (doc, failed) = apply(good);
        for h in failed {
            skipped.extend(parsed[&h].1.iter().copied());
        }
        skipped.sort();
        skipped.dedup();
        Ok(Materialized {
            state: doc,
            skipped,
        })
    }
}

/// True if `payload` is one Automerge change that [`AutomergeMerger`] can read.
pub fn is_change(payload: &[u8]) -> bool {
    parse(payload).is_some()
}

/// Parse a payload as one Automerge change, refusing anything that is not a change
/// chunk or would decompress to more than [`MAX_CHANGE_BYTES`].
fn parse(payload: &[u8]) -> Option<automerge::Change> {
    if payload.len() as u64 > MAX_CHANGE_BYTES {
        return None;
    }
    // Chunk header: 4 magic bytes, 4 checksum bytes, the chunk type, the length (LEB128).
    match payload.get(8)? {
        1 => {}
        2 => {
            let data = payload.get(9 + leb128_len(payload.get(9..)?)?..)?;
            let mut inflated = flate2::read::DeflateDecoder::new(data).take(MAX_CHANGE_BYTES + 1);
            let n = std::io::copy(&mut inflated, &mut std::io::sink()).ok()?;
            if n > MAX_CHANGE_BYTES {
                return None;
            }
        }
        _ => return None,
    }
    automerge::Change::from_bytes(payload.to_vec()).ok()
}

/// The number of bytes of the unsigned LEB128 number at the start of `b`.
fn leb128_len(b: &[u8]) -> Option<usize> {
    b.iter().take(10).position(|x| x & 0x80 == 0).map(|i| i + 1)
}

/// What the checks remember about an operation.
struct OpInfo {
    obj: ObjectId,
    insert: bool,
    /// Sequence number of the change that made it (its actor is in the op ID).
    seq: u64,
}

/// Check the changes in causal order (ties by hash). Returns the good ones in that
/// order and the bad ones (failed a check, or depend on one that did). Changes
/// whose dependencies are missing are in neither: Automerge would wait for them.
fn check_in_causal_order(
    parsed: &HashMap<ChangeHash, (automerge::Change, Vec<ChangeId>)>,
) -> (Vec<ChangeHash>, Vec<ChangeHash>) {
    let mut waiting: HashMap<ChangeHash, usize> = HashMap::new();
    let mut children: HashMap<ChangeHash, Vec<ChangeHash>> = HashMap::new();
    let mut ready = BTreeSet::new();
    for (h, (ac, _)) in parsed {
        let deps: HashSet<&ChangeHash> = ac.deps().iter().collect();
        for d in &deps {
            children.entry(**d).or_default().push(*h);
        }
        if deps.is_empty() {
            ready.insert(*h);
        } else {
            waiting.insert(*h, deps.len());
        }
    }
    let mut ops: HashMap<OpId, OpInfo> = HashMap::new();
    // Object -> (type, depth); the root map has depth 0.
    let mut objects: HashMap<OpId, (automerge::ObjType, usize)> = HashMap::new();
    let mut clocks: HashMap<ChangeHash, HashMap<ActorId, u64>> = HashMap::new();
    let (mut good, mut bad) = (Vec::new(), HashSet::new());
    while let Some(h) = ready.pop_first() {
        let ac = &parsed[&h].0;
        let ok = !ac.deps().iter().any(|d| bad.contains(d))
            && check(ac, &mut ops, &mut objects, &mut clocks);
        if ok {
            good.push(h);
        } else {
            bad.insert(h);
        }
        for c in children.get(&h).into_iter().flatten() {
            if let Some(n) = waiting.get_mut(c) {
                *n -= 1;
                if *n == 0 {
                    waiting.remove(c);
                    ready.insert(*c);
                }
            }
        }
    }
    let mut bad: Vec<_> = bad.into_iter().collect();
    bad.sort();
    (good, bad)
}

/// Check one change whose dependencies were all checked (see the type docs) and
/// remember its operations if it passes.
fn check(
    ac: &automerge::Change,
    ops: &mut HashMap<OpId, OpInfo>,
    objects: &mut HashMap<OpId, (automerge::ObjType, usize)>,
    clocks: &mut HashMap<ChangeHash, HashMap<ActorId, u64>>,
) -> bool {
    use automerge::ObjType;
    let ex = ac.decode();
    let (actor, seq) = (ex.actor_id.clone(), ex.seq);
    // What this change has seen: the latest change of each actor in its history.
    let mut clock: HashMap<ActorId, u64> = HashMap::new();
    for d in ac.deps() {
        for (a, s) in clocks.get(d).into_iter().flatten() {
            let e = clock.entry(a.clone()).or_default();
            *e = (*e).max(*s);
        }
    }
    // An actor's changes form a chain: each builds on the actor's previous one.
    if seq == 0 || clock.get(&actor).copied().unwrap_or(0) != seq - 1 {
        return false;
    }
    clock.insert(actor.clone(), seq);
    let mut new_ops: Vec<(OpId, OpInfo)> = Vec::new();
    let mut new_objects: HashMap<OpId, (ObjType, usize)> = HashMap::new();
    let start = ex.start_op.get();
    for (i, op) in ex.operations.iter().enumerate() {
        let id = OpId(start + i as u64, actor.clone());
        let mine = |x: &OpId| new_ops.iter().find(|(o, _)| o == x).map(|(_, i)| i);
        if ops.contains_key(&id) || mine(&id).is_some() {
            return false;
        }
        let (otype, depth) = match &op.obj {
            ObjectId::Root => (ObjType::Map, 0),
            ObjectId::Id(o) => match new_objects
                .get(o)
                .or_else(|| visible(o, ops, &clock).and_then(|_| objects.get(o)))
            {
                Some(x) => *x,
                None => return false,
            },
        };
        let is_seq = matches!(otype, ObjType::List | ObjType::Text);
        match &op.key {
            Key::Map(_) if is_seq || op.insert => return false,
            Key::Map(_) => {}
            Key::Seq(_) if !is_seq => return false,
            Key::Seq(ElementId::Head) if !op.insert => return false,
            Key::Seq(ElementId::Head) => {}
            Key::Seq(ElementId::Id(e)) => match mine(e).or_else(|| visible(e, ops, &clock)) {
                Some(i) if i.insert && i.obj == op.obj => {}
                _ => return false,
            },
        }
        for p in op.pred.iter() {
            match mine(p).or_else(|| visible(p, ops, &clock)) {
                Some(i) if i.obj == op.obj => {}
                _ => return false,
            }
        }
        match &op.action {
            OpType::Make(t) => {
                if depth + 1 > MAX_DEPTH {
                    return false;
                }
                new_objects.insert(id.clone(), (*t, depth + 1));
            }
            OpType::MarkBegin(_) | OpType::MarkEnd(_) if !is_seq => return false,
            _ => {}
        }
        new_ops.push((
            id,
            OpInfo {
                obj: op.obj.clone(),
                insert: op.insert,
                seq,
            },
        ));
    }
    ops.extend(new_ops);
    objects.extend(new_objects);
    clocks.insert(ac.hash(), clock);
    true
}

/// The operation `id`, if the change with `clock` has seen it.
fn visible<'a>(
    id: &OpId,
    ops: &'a HashMap<OpId, OpInfo>,
    clock: &HashMap<ActorId, u64>,
) -> Option<&'a OpInfo> {
    ops.get(id)
        .filter(|i| clock.get(&id.1).is_some_and(|s| i.seq <= *s))
}

/// Apply checked changes. Should Automerge still fail or panic on one, apply them
/// one at a time and leave out those that do (a panic can only be caught where
/// panics unwind, not in WebAssembly builds).
fn apply(changes: Vec<automerge::Change>) -> (AutoCommit, Vec<ChangeHash>) {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let try_apply = |doc: &mut AutoCommit, cs: Vec<automerge::Change>| {
        matches!(
            catch_unwind(AssertUnwindSafe(|| doc.apply_changes(cs))),
            Ok(Ok(()))
        )
    };
    let mut doc = AutoCommit::new();
    if try_apply(&mut doc, changes.clone()) {
        return (doc, Vec::new());
    }
    let (mut kept, mut failed) = (Vec::new(), Vec::new());
    doc = AutoCommit::new();
    for c in changes {
        if failed.iter().any(|f| c.deps().contains(f)) {
            failed.push(c.hash());
        } else if try_apply(&mut doc, vec![c.clone()]) {
            kept.push(c);
        } else {
            failed.push(c.hash());
            doc = AutoCommit::new();
            doc.apply_changes(kept.clone())
                .expect("these changes applied before");
        }
    }
    (doc, failed)
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

// ---- JSON documents ----
//
// The bindings expose Automerge documents as JSON: read the merged state with
// [`to_json`], change it with an RFC 7396 merge patch ([`merge_patch`]). Objects
// merge per key, so concurrent patches of different keys both survive; arrays
// and scalars are replaced as a whole (last writer by Automerge's rules wins).

use automerge::{ObjId, ObjType, ReadDoc, ScalarValue, Value};
use serde_json::{Map, Number, Value as Json};

/// The document as JSON. Text objects become strings, counters and timestamps
/// numbers, bytes arrays of numbers. Objects nested deeper than [`MAX_DEPTH`]
/// read as `null`.
pub fn to_json(doc: &AutoCommit) -> Json {
    obj_json(doc, &automerge::ROOT, 0)
}

fn obj_json(doc: &AutoCommit, obj: &ObjId, depth: usize) -> Json {
    if depth > MAX_DEPTH {
        return Json::Null;
    }
    match doc.object_type(obj) {
        Ok(ObjType::Map) | Ok(ObjType::Table) => {
            let mut m = Map::new();
            for key in doc.keys(obj) {
                if let Ok(Some((v, id))) = doc.get(obj, key.as_str()) {
                    m.insert(key, value_json(doc, v, &id, depth));
                }
            }
            Json::Object(m)
        }
        Ok(ObjType::List) => Json::Array(
            (0..doc.length(obj))
                .filter_map(|i| doc.get(obj, i).ok().flatten())
                .map(|(v, id)| value_json(doc, v, &id, depth))
                .collect(),
        ),
        Ok(ObjType::Text) => Json::String(doc.text(obj).unwrap_or_default()),
        Err(_) => Json::Null,
    }
}

fn value_json(doc: &AutoCommit, v: Value<'_>, id: &ObjId, depth: usize) -> Json {
    match v {
        Value::Object(_) => obj_json(doc, id, depth + 1),
        Value::Scalar(s) => match s.as_ref() {
            ScalarValue::Str(s) => Json::String(s.to_string()),
            ScalarValue::Int(i) | ScalarValue::Timestamp(i) => Json::from(*i),
            ScalarValue::Uint(u) => Json::from(*u),
            ScalarValue::F64(f) => Number::from_f64(*f).map_or(Json::Null, Json::Number),
            ScalarValue::Counter(c) => Json::from(i64::from(c)),
            ScalarValue::Boolean(b) => Json::Bool(*b),
            ScalarValue::Bytes(b) => Json::Array(b.iter().map(|x| Json::from(*x)).collect()),
            ScalarValue::Null | ScalarValue::Unknown { .. } => Json::Null,
        },
    }
}

/// Apply an RFC 7396 JSON merge patch to the document root: `null` deletes a
/// key, an object merges into the existing map (created if needed), anything
/// else replaces the value. The patch must be a JSON object nested at most
/// [`MAX_DEPTH`] deep.
pub fn merge_patch(doc: &mut AutoCommit, patch: &Json) -> Result<(), AutomergeError> {
    let Json::Object(patch) = patch else {
        return Err(AutomergeError::InvalidOp(ObjType::Map));
    };
    if too_deep(patch) {
        return Err(AutomergeError::Fail);
    }
    patch_map(doc, &automerge::ROOT, patch)
}

/// Whether `patch` nests objects deeper than [`MAX_DEPTH`] (checked without recursion).
fn too_deep(patch: &Map<String, Json>) -> bool {
    let mut stack: Vec<(&Json, usize)> = patch.values().map(|v| (v, 1)).collect();
    while let Some((v, d)) = stack.pop() {
        let inner: Box<dyn Iterator<Item = &Json>> = match v {
            Json::Object(m) => Box::new(m.values()),
            Json::Array(a) => Box::new(a.iter()),
            _ => continue,
        };
        if d > MAX_DEPTH {
            return true;
        }
        stack.extend(inner.map(|x| (x, d + 1)));
    }
    false
}

fn patch_map(
    doc: &mut AutoCommit,
    obj: &ObjId,
    patch: &Map<String, Json>,
) -> Result<(), AutomergeError> {
    for (key, value) in patch {
        match value {
            Json::Null => {
                if doc.get(obj, key.as_str())?.is_some() {
                    doc.delete(obj, key.as_str())?;
                }
            }
            Json::Object(inner) => {
                let existing = match doc.get(obj, key.as_str())? {
                    Some((Value::Object(ObjType::Map), id)) => id,
                    _ => doc.put_object(obj, key.as_str(), ObjType::Map)?,
                };
                patch_map(doc, &existing, inner)?;
            }
            Json::Array(items) => {
                let list = doc.put_object(obj, key.as_str(), ObjType::List)?;
                fill_list(doc, &list, items)?;
            }
            scalar => {
                // Unchanged values are not rewritten, so a patch that repeats the
                // current state produces no change and cannot clobber concurrent edits.
                let new = scalar_of(scalar);
                let same = matches!(
                    doc.get(obj, key.as_str())?,
                    Some((Value::Scalar(old), _)) if *old == new
                );
                if !same {
                    doc.put(obj, key.as_str(), new)?;
                }
            }
        }
    }
    Ok(())
}

fn fill_list(doc: &mut AutoCommit, list: &ObjId, items: &[Json]) -> Result<(), AutomergeError> {
    for (i, item) in items.iter().enumerate() {
        match item {
            Json::Object(m) => {
                let id = doc.insert_object(list, i, ObjType::Map)?;
                patch_map(doc, &id, m)?;
            }
            Json::Array(inner) => {
                let id = doc.insert_object(list, i, ObjType::List)?;
                fill_list(doc, &id, inner)?;
            }
            scalar => doc.insert(list, i, scalar_of(scalar))?,
        }
    }
    Ok(())
}

fn scalar_of(v: &Json) -> ScalarValue {
    match v {
        Json::Bool(b) => ScalarValue::Boolean(*b),
        Json::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => ScalarValue::Int(i),
            (None, Some(u)) => ScalarValue::Uint(u),
            _ => ScalarValue::F64(n.as_f64().unwrap_or(0.0)),
        },
        Json::String(s) => ScalarValue::Str(s.as_str().into()),
        _ => ScalarValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc_from(patch: Json) -> AutoCommit {
        let mut d = AutoCommit::new();
        merge_patch(&mut d, &patch).unwrap();
        d
    }

    #[test]
    fn json_roundtrip() {
        let v = json!({
            "title": "x", "n": -3, "big": 18446744073709551615u64, "f": 1.5,
            "ok": true, "tags": ["a", 1, {"k": [true]}], "nested": {"a": {"b": "c"}}
        });
        assert_eq!(to_json(&doc_from(v.clone())), v);
    }

    #[test]
    fn merge_patch_follows_rfc_7396() {
        let mut d = doc_from(json!({"a": "b", "c": {"d": "e", "f": "g"}, "keep": 1}));
        merge_patch(&mut d, &json!({"a": "z", "c": {"f": null}, "new": [1]})).unwrap();
        assert_eq!(
            to_json(&d),
            json!({"a": "z", "c": {"d": "e"}, "keep": 1, "new": [1]})
        );
        // Removing a missing key is fine; a non-object patch is not.
        merge_patch(&mut d, &json!({"missing": null})).unwrap();
        assert!(merge_patch(&mut d, &json!([1])).is_err());
        // A scalar replaces a map and the other way round.
        merge_patch(&mut d, &json!({"c": 5, "a": {"x": 1}})).unwrap();
        assert_eq!(to_json(&d)["c"], json!(5));
        assert_eq!(to_json(&d)["a"], json!({"x": 1}));
    }

    #[test]
    fn repeating_the_state_is_no_change() {
        let mut d = doc_from(json!({"a": "b", "n": 1}));
        let payload = author(&mut d, |d| merge_patch(d, &json!({"a": "b", "n": 1}))).unwrap();
        assert!(payload.is_none());
    }
}
