//! Two devices edit the same Automerge object concurrently and converge.

use automerge::transaction::Transactable;
use automerge::{ROOT, ReadDoc};
use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use kith_merge::Merger;
use kith_merge::automerge_merger::{AutomergeMerger, author, put_str};

fn client() -> Client<MemoryStore> {
    Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap()
}

fn text(c: &Client<MemoryStore>, oid: &ObjectId, key: &str) -> Option<String> {
    let doc = c.materialize(oid, &AutomergeMerger).unwrap().state;
    doc.get(ROOT, key)
        .unwrap()
        .and_then(|(v, _)| v.into_string().ok())
}

/// Apply `f` to the current merged state of `oid` on `c` and commit the result as an edit.
fn edit(
    c: &mut Client<MemoryStore>,
    oid: ObjectId,
    f: impl FnOnce(&mut automerge::AutoCommit) -> Result<(), automerge::AutomergeError>,
) -> kith_client::Change {
    let mut doc = c.materialize(&oid, &AutomergeMerger).unwrap().state;
    let payload = author(&mut doc, f)
        .unwrap()
        .expect("edit changed something");
    c.edit(oid, payload).unwrap()
}

fn setup() -> (Client<MemoryStore>, Client<MemoryStore>, ObjectId) {
    let mut a = client();
    let mut b = client();
    let mut doc = automerge::AutoCommit::new();
    let payload = author(&mut doc, |d| put_str(d, "title", "draft"))
        .unwrap()
        .unwrap();
    let created = a.create(ObjectType::new("acme.todo"), payload).unwrap();
    let oid = created.body.object_id;
    b.receive(created).unwrap();
    (a, b, oid)
}

fn exchange(a: &mut Client<MemoryStore>, b: &mut Client<MemoryStore>, oid: &ObjectId) {
    let from_a = a.history(oid).unwrap();
    let from_b = b.history(oid).unwrap();
    for c in from_a {
        b.receive(c).unwrap();
    }
    for c in from_b {
        a.receive(c).unwrap();
    }
}

/// req: REQ-DATA-004
#[test]
fn concurrent_edits_of_different_fields_both_survive() {
    let (mut a, mut b, oid) = setup();
    edit(&mut a, oid, |d| put_str(d, "owner", "ann"));
    edit(&mut b, oid, |d| d.put(ROOT, "done", true));
    assert_eq!(
        a.store().heads(&oid).unwrap().len(),
        1,
        "no fork before exchange"
    );

    exchange(&mut a, &mut b, &oid);

    assert_eq!(
        a.store().heads(&oid).unwrap().len(),
        2,
        "kith history forks"
    );
    for c in [&a, &b] {
        assert_eq!(text(c, &oid, "title").as_deref(), Some("draft"));
        assert_eq!(text(c, &oid, "owner").as_deref(), Some("ann"));
        let doc = c.materialize(&oid, &AutomergeMerger).unwrap().state;
        assert!(doc.get(ROOT, "done").unwrap().unwrap().0.as_bool().unwrap());
    }
}

/// req: REQ-DATA-004
#[test]
fn conflicting_edits_pick_the_same_winner_everywhere() {
    let (mut a, mut b, oid) = setup();
    edit(&mut a, oid, |d| put_str(d, "title", "from a"));
    edit(&mut b, oid, |d| put_str(d, "title", "from b"));
    exchange(&mut a, &mut b, &oid);

    let winner = text(&a, &oid, "title").unwrap();
    assert!(winner == "from a" || winner == "from b");
    assert_eq!(text(&b, &oid, "title").unwrap(), winner);
}

/// req: REQ-DATA-004
#[test]
fn merge_does_not_depend_on_arrival_order() {
    let (mut a, mut b, oid) = setup();
    edit(&mut a, oid, |d| put_str(d, "title", "from a"));
    edit(&mut b, oid, |d| put_str(d, "title", "from b"));
    exchange(&mut a, &mut b, &oid);

    let mut history = a.history(&oid).unwrap();
    let forward = AutomergeMerger.materialize(&history).unwrap();
    history.reverse();
    let reversed = AutomergeMerger.materialize(&history).unwrap();
    let (mut f, mut r) = (forward.state, reversed.state);
    // Same heads means the same set of Automerge changes. (`save()` bytes are not
    // canonical across apply orders, so compare the contents instead.)
    assert_eq!(f.get_heads(), r.get_heads());
    for key in ["title", "owner"] {
        let get = |d: &automerge::AutoCommit| {
            d.get(ROOT, key)
                .unwrap()
                .and_then(|(v, _)| v.into_string().ok())
        };
        assert_eq!(get(&f), get(&r), "{key}");
    }
}

/// req: REQ-DATA-004
#[test]
fn next_edit_joins_the_fork() {
    let (mut a, mut b, oid) = setup();
    edit(&mut a, oid, |d| put_str(d, "owner", "ann"));
    edit(&mut b, oid, |d| put_str(d, "title", "final"));
    exchange(&mut a, &mut b, &oid);
    assert_eq!(a.store().heads(&oid).unwrap().len(), 2);

    let joined = edit(&mut a, oid, |d| put_str(d, "note", "merged"));
    assert_eq!(joined.body.parents.len(), 2, "names both heads");
    assert_eq!(a.store().heads(&oid).unwrap(), vec![joined.change_id]);
}

/// req: REQ-DATA-004
#[test]
fn undecodable_payload_is_skipped_not_fatal() {
    let (mut a, _b, oid) = setup();
    let bad = a.edit(oid, b"not an automerge change".to_vec()).unwrap();
    let m = a.materialize(&oid, &AutomergeMerger).unwrap();
    assert_eq!(m.skipped, vec![bad.change_id]);
    assert_eq!(
        m.state
            .get(ROOT, "title")
            .unwrap()
            .and_then(|(v, _)| v.into_string().ok())
            .as_deref(),
        Some("draft")
    );
}

#[test]
fn unknown_object_is_an_error() {
    let c = client();
    assert!(
        c.materialize(&ObjectId::random(), &AutomergeMerger)
            .is_err()
    );
}
