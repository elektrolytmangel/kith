//! Two devices edit offline, then catch up with each other.
//! Run: `cargo run -p example-two-devices`

use kith_client::{Client, DeviceKey, MemoryStore, ObjectType, Store};

fn main() {
    let mut laptop = Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap();
    let mut phone = Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap();

    let note = laptop
        .create(ObjectType::new("note"), b"groceries: milk".to_vec())
        .unwrap();
    let oid = note.body.object_id;
    phone.receive(note).unwrap();

    // Both edit while offline.
    laptop.edit(oid, b"groceries: milk, eggs".to_vec()).unwrap();
    phone.edit(oid, b"groceries: milk, bread".to_vec()).unwrap();

    // Catch-up: exchange only what the other side is missing.
    let d = kith_sync::diff(
        &laptop.store().all_ids().unwrap(),
        &phone.store().all_ids().unwrap(),
    );
    for id in d.to_send {
        phone
            .receive(laptop.store().get(&id).unwrap().unwrap())
            .unwrap();
    }
    for id in d.to_request {
        laptop
            .receive(phone.store().get(&id).unwrap().unwrap())
            .unwrap();
    }

    let heads = laptop.store().heads(&oid).unwrap();
    println!("history: {} changes", laptop.history(&oid).unwrap().len());
    println!(
        "heads after sync: {} (fork to be merged by the CRDT layer)",
        heads.len()
    );
    assert_eq!(heads, phone.store().heads(&oid).unwrap());
}
