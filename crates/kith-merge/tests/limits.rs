//! Changes Automerge must not apply as they are: references to objects, elements or
//! operations a change has not seen, nesting beyond the limit, oversized payloads.
// Integration tests: helpers may unwrap (clippy.toml only exempts #[test] functions).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjType, ROOT, ReadDoc};
use kith_client::{Change, Client, DeviceKey, MemoryStore, ObjectId, ObjectType};
use kith_merge::Merger;
use kith_merge::automerge_merger::{
    AutomergeMerger, MAX_CHANGE_BYTES, MAX_DEPTH, author, merge_patch, to_json,
};
use serde_json::{Value as Json, json};

fn setup() -> (Client<MemoryStore>, ObjectId) {
    let mut c = Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap();
    let mut doc = AutoCommit::new();
    let payload = author(&mut doc, |d| merge_patch(d, &json!({"title": "draft"})))
        .unwrap()
        .unwrap();
    let oid = c
        .create(ObjectType::new("acme.todo"), payload)
        .unwrap()
        .body
        .object_id;
    (c, oid)
}

/// The payload of `edit` applied to the current state (not stored).
fn payload(
    c: &Client<MemoryStore>,
    oid: &ObjectId,
    edit: impl FnOnce(&mut AutoCommit) -> Result<(), automerge::AutomergeError>,
) -> Vec<u8> {
    let mut doc = c.materialize(oid, &AutomergeMerger).unwrap().state;
    author(&mut doc, edit).unwrap().unwrap()
}

/// `payload` re-encoded after `f` changed its expanded (JSON) form.
fn forge(payload: &[u8], f: impl FnOnce(&mut Json)) -> Vec<u8> {
    let ex = automerge::Change::from_bytes(payload.to_vec())
        .unwrap()
        .decode();
    let mut j = serde_json::to_value(&ex).unwrap();
    j.as_object_mut().unwrap().remove("hash");
    f(&mut j);
    let ex: automerge::ExpandedChange = serde_json::from_value(j).unwrap();
    automerge::Change::from(ex).raw_bytes().to_vec()
}

fn hash_of(payload: &[u8]) -> String {
    automerge::Change::from_bytes(payload.to_vec())
        .unwrap()
        .hash()
        .to_string()
}

fn title(c: &Client<MemoryStore>, oid: &ObjectId) -> Json {
    to_json(&c.materialize(oid, &AutomergeMerger).unwrap().state)["title"].clone()
}

fn skipped(c: &Client<MemoryStore>, oid: &ObjectId) -> Vec<kith_client::ChangeId> {
    c.materialize(oid, &AutomergeMerger).unwrap().skipped
}

fn add(c: &mut Client<MemoryStore>, oid: ObjectId, payload: Vec<u8>) -> Change {
    c.edit(oid, payload).unwrap()
}

/// req: REQ-DATA-004
#[test]
fn changes_referring_to_what_they_have_not_seen_are_skipped_with_their_descendants() {
    let (mut c, oid) = setup();
    let good = payload(&c, &oid, |d| merge_patch(d, &json!({"a": {"b": 1}})));
    // An op inside an object nobody created (Automerge 0.12 panics on this).
    let missing_obj = forge(&good, |j| {
        let actor = j["actor"].as_str().unwrap().to_string();
        j["ops"][1]["obj"] = json!(format!("99@{actor}"));
    });
    // A child of that change.
    let child = forge(
        &payload(&c, &oid, |d| merge_patch(d, &json!({"x": 1}))),
        |j| j["deps"] = json!([hash_of(&missing_obj)]),
    );
    // An overwrite of an operation that does not exist.
    let missing_pred = forge(
        &payload(&c, &oid, |d| merge_patch(d, &json!({"title": "z"}))),
        |j| {
            let actor = j["actor"].as_str().unwrap().to_string();
            j["ops"][0]["pred"] = json!([format!("77@{actor}")]);
        },
    );
    // A change that skips ahead in its actor's sequence.
    let seq_gap = forge(
        &payload(&c, &oid, |d| merge_patch(d, &json!({"y": 1}))),
        |j| j["seq"] = json!(5),
    );
    let mut bad: Vec<_> = [missing_obj, child, missing_pred, seq_gap]
        .into_iter()
        .map(|p| add(&mut c, oid, p).change_id)
        .collect();
    let done = payload(&c, &oid, |d| merge_patch(d, &json!({"done": true})));
    let fine = add(&mut c, oid, done);
    bad.sort();
    assert_eq!(skipped(&c, &oid), bad);
    let state = to_json(&c.materialize(&oid, &AutomergeMerger).unwrap().state);
    assert_eq!(state, json!({"title": "draft", "done": true}), "{fine:?}");

    // The same result for any order of the history.
    let mut history = c.history(&oid).unwrap();
    history.reverse();
    let m = AutomergeMerger.materialize(&history).unwrap();
    assert_eq!(m.skipped, bad);
    assert_eq!(to_json(&m.state), state);
}

/// req: REQ-DATA-004
#[test]
fn nesting_beyond_the_limit_is_skipped_and_never_read() {
    let (mut c, oid) = setup();
    let nest = |depth: usize| {
        payload(&c, &oid, move |d| {
            let mut obj = ROOT;
            for _ in 0..depth {
                obj = d.put_object(&obj, "n", ObjType::Map)?;
            }
            Ok(())
        })
    };
    let (ok, deep) = (nest(MAX_DEPTH), nest(MAX_DEPTH + 1));
    let ok = add(&mut c, oid, ok);
    let deep = add(&mut c, oid, deep);
    assert_eq!(skipped(&c, &oid), vec![deep.change_id], "{ok:?}");
    assert_eq!(title(&c, &oid), json!("draft"));

    // Reading a document that is deeper anyway stops at the limit.
    let mut doc = AutoCommit::new();
    let mut obj = ROOT;
    for _ in 0..50_000 {
        obj = doc.put_object(&obj, "n", ObjType::Map).unwrap();
    }
    let mut j = &to_json(&doc);
    let mut depth = 0;
    while let Some(inner) = j.get("n") {
        j = inner;
        depth += 1;
    }
    // MAX_DEPTH maps, then the next one reads as null.
    assert_eq!(depth, MAX_DEPTH + 1);
    assert_eq!(*j, Json::Null);

    // Patches are held to the same limit.
    let patch = |depth: usize| {
        let mut p = json!(1);
        for _ in 0..depth {
            p = json!({ "n": p });
        }
        p
    };
    // The outermost object of a patch is the document root.
    assert!(merge_patch(&mut AutoCommit::new(), &patch(MAX_DEPTH + 1)).is_ok());
    assert!(merge_patch(&mut AutoCommit::new(), &patch(MAX_DEPTH + 2)).is_err());
}

/// req: REQ-DATA-004
#[test]
fn compressed_changes_count_with_their_inflated_size() {
    let (mut c, oid) = setup();
    // A real compressed change is fine.
    let big = "x".repeat(64 * 1024);
    let raw = payload(&c, &oid, |d| d.put(ROOT, "big", big.as_str()));
    let compressed = automerge::Change::from_bytes(raw)
        .unwrap()
        .bytes()
        .into_owned();
    assert_eq!(compressed[8], 2, "a compressed chunk");
    add(&mut c, oid, compressed);
    assert!(skipped(&c, &oid).is_empty());
    let doc = c.materialize(&oid, &AutomergeMerger).unwrap().state;
    assert!(doc.get(ROOT, "big").unwrap().is_some());

    // One that inflates beyond the limit is not even parsed.
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    let zeros = vec![0u8; 1024 * 1024];
    for _ in 0..=(MAX_CHANGE_BYTES / zeros.len() as u64) {
        z.write_all(&zeros).unwrap();
    }
    let data = z.finish().unwrap();
    let mut bomb = vec![0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 2];
    let mut n = data.len();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            bomb.push(b);
            break;
        }
        bomb.push(b | 0x80);
    }
    bomb.extend(data);
    let bomb = add(&mut c, oid, bomb);
    assert_eq!(skipped(&c, &oid), vec![bomb.change_id]);
    assert_eq!(title(&c, &oid), json!("draft"));
}
