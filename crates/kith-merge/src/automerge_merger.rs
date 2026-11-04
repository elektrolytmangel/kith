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

// ---- JSON documents ----
//
// The bindings expose Automerge documents as JSON: read the merged state with
// [`to_json`], change it with an RFC 7396 merge patch ([`merge_patch`]). Objects
// merge per key, so concurrent patches of different keys both survive; arrays
// and scalars are replaced as a whole (last writer by Automerge's rules wins).

use automerge::{ObjId, ObjType, ReadDoc, ScalarValue, Value};
use serde_json::{Map, Number, Value as Json};

/// The document as JSON. Text objects become strings, counters and timestamps
/// numbers, bytes arrays of numbers.
pub fn to_json(doc: &AutoCommit) -> Json {
    obj_json(doc, &automerge::ROOT)
}

fn obj_json(doc: &AutoCommit, obj: &ObjId) -> Json {
    match doc.object_type(obj) {
        Ok(ObjType::Map) | Ok(ObjType::Table) => {
            let mut m = Map::new();
            for key in doc.keys(obj) {
                if let Ok(Some((v, id))) = doc.get(obj, key.as_str()) {
                    m.insert(key, value_json(doc, v, &id));
                }
            }
            Json::Object(m)
        }
        Ok(ObjType::List) => Json::Array(
            (0..doc.length(obj))
                .filter_map(|i| doc.get(obj, i).ok().flatten())
                .map(|(v, id)| value_json(doc, v, &id))
                .collect(),
        ),
        Ok(ObjType::Text) => Json::String(doc.text(obj).unwrap_or_default()),
        Err(_) => Json::Null,
    }
}

fn value_json(doc: &AutoCommit, v: Value<'_>, id: &ObjId) -> Json {
    match v {
        Value::Object(_) => obj_json(doc, id),
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
/// else replaces the value. The patch must be a JSON object.
pub fn merge_patch(doc: &mut AutoCommit, patch: &Json) -> Result<(), AutomergeError> {
    let Json::Object(patch) = patch else {
        return Err(AutomergeError::InvalidOp(ObjType::Map));
    };
    patch_map(doc, &automerge::ROOT, patch)
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
