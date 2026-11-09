use super::*;
use kith_crypto::DeviceKey;

fn change(key: &DeviceKey, object: ObjectId, parents: Vec<ChangeId>, payload: &[u8]) -> Change {
    Change::sign(
        UnsignedChange {
            scope: Scope::local(),
            object_id: object,
            object_type: ObjectType::new("note"),
            parents,
            timestamp_ms: 1_700_000_000_000,
            payload: payload.to_vec(),
        },
        key,
    )
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("kith-{name}-{}.db", ObjectId::random()));
    let _ = std::fs::remove_file(&p);
    p
}

/// req: REQ-STORE-003
#[cfg(unix)]
#[test]
fn database_files_are_readable_by_the_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let path = temp_path("mode");
    {
        let mut s = SqliteStore::open(&path).unwrap();
        s.put_meta("mls", b"state").unwrap();
        assert_eq!(mode(&path), 0o600);
        let mut wal = path.clone().into_os_string();
        wal.push("-wal");
        assert_eq!(mode(std::path::Path::new(&wal)), 0o600);
    }
    // A file left world-readable by an older version is tightened on open.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(SqliteStore::open(&path).unwrap());
    assert_eq!(mode(&path), 0o600);
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.clone().into_os_string();
        p.push(suffix);
        let _ = std::fs::remove_file(p);
    }
}

/// req: REQ-DATA-005
#[test]
fn deleted_changes_and_chunks_are_gone_from_both_stores() {
    fn check(s: &mut dyn Store) {
        let key = DeviceKey::generate();
        let o = ObjectId::random();
        let a = change(&key, o, vec![], b"a");
        let b = change(&key, o, vec![a.change_id], b"b");
        let c = change(&key, o, vec![b.change_id], b"c");
        for x in [&a, &b, &c] {
            s.put(x.clone()).unwrap();
        }
        s.put_chunk(&[7; 32], &Scope::local(), b"data").unwrap();
        s.delete(&[a.change_id, b.change_id, ChangeId([9; 32])])
            .unwrap();
        s.delete_chunk(&[7; 32]).unwrap();
        assert!(!s.contains(&a.change_id).unwrap());
        assert!(s.get(&b.change_id).unwrap().is_none());
        assert_eq!(s.history(&o).unwrap(), vec![c.clone()]);
        assert_eq!(s.all_ids().unwrap(), vec![c.change_id]);
        assert_eq!(s.scope_ids(&Scope::local()).unwrap(), vec![c.change_id]);
        assert!(s.get_chunk(&[7; 32]).unwrap().is_none());
        // A deleted change can be stored again (a peer may send it).
        assert!(s.put(a).unwrap());
    }
    check(&mut SqliteStore::open_in_memory().unwrap());
    check(&mut crate::MemoryStore::new());
}

/// req: REQ-STORE-001
#[test]
fn heads_ignore_children_in_other_objects() {
    let key = DeviceKey::generate();
    let (a, b) = (ObjectId::random(), ObjectId::random());
    let a1 = change(&key, a, vec![], b"a1");
    // A change in another object that names a1 as its parent.
    let b1 = change(&key, b, vec![a1.change_id], b"b1");
    let mut sql = SqliteStore::open_in_memory().unwrap();
    let mut mem = crate::MemoryStore::new();
    for c in [&a1, &b1] {
        sql.put(c.clone()).unwrap();
        mem.put(c.clone()).unwrap();
    }
    assert_eq!(sql.heads(&a).unwrap(), vec![a1.change_id]);
    assert_eq!(sql.heads(&a).unwrap(), mem.heads(&a).unwrap());
    assert_eq!(sql.heads(&b).unwrap(), mem.heads(&b).unwrap());
}

/// req: REQ-STORE-001
#[test]
fn roundtrip_preserves_change_and_signature() {
    let key = DeviceKey::generate();
    let mut s = SqliteStore::open_in_memory().unwrap();
    let oid = ObjectId::random();
    let c1 = change(&key, oid, vec![], b"v1");
    let c2 = change(&key, oid, vec![c1.change_id], b"v2");
    assert!(s.put(c1.clone()).unwrap());
    assert!(s.put(c2.clone()).unwrap());
    assert!(!s.put(c2.clone()).unwrap(), "duplicate is a no-op");

    assert_eq!(s.get(&c2.change_id).unwrap().unwrap(), c2);
    s.get(&c1.change_id).unwrap().unwrap().verify().unwrap();
    assert_eq!(s.history(&oid).unwrap(), vec![c1.clone(), c2.clone()]);
    assert_eq!(s.heads(&oid).unwrap(), vec![c2.change_id]);
    assert!(s.contains(&c1.change_id).unwrap());
    assert_eq!(s.all_ids().unwrap(), vec![c1.change_id, c2.change_id]);
}

/// req: REQ-STORE-001
#[test]
fn data_survives_reopen() {
    let path = temp_path("reopen");
    let key = DeviceKey::generate();
    let oid = ObjectId::random();
    let c = change(&key, oid, vec![], b"persist");
    {
        let mut s = SqliteStore::open(&path).unwrap();
        s.put(c.clone()).unwrap();
    }
    {
        let mut s = SqliteStore::open(&path).unwrap();
        assert_eq!(s.get_meta("mls").unwrap(), None);
        s.put_meta("mls", b"one").unwrap();
        s.put_meta("mls", b"two").unwrap();
    }
    {
        let mut s = SqliteStore::open(&path).unwrap();
        s.put_chunk(&[7; 32], &Scope::local(), b"chunk").unwrap();
    }
    let s = SqliteStore::open(&path).unwrap();
    assert_eq!(s.history(&oid).unwrap(), vec![c]);
    assert_eq!(s.get_meta("mls").unwrap(), Some(b"two".to_vec()));
    assert_eq!(
        s.get_chunk(&[7; 32]).unwrap(),
        Some((Scope::local(), b"chunk".to_vec()))
    );
    assert_eq!(s.get_chunk(&[8; 32]).unwrap(), None);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

/// req: REQ-STORE-001
#[test]
fn forks_have_two_heads() {
    let key = DeviceKey::generate();
    let mut s = SqliteStore::open_in_memory().unwrap();
    let oid = ObjectId::random();
    let root = change(&key, oid, vec![], b"root");
    let a = change(&key, oid, vec![root.change_id], b"a");
    let b = change(&key, oid, vec![root.change_id], b"b");
    for c in [&root, &a, &b] {
        s.put(c.clone()).unwrap();
    }
    let mut want = vec![a.change_id, b.change_id];
    want.sort();
    assert_eq!(s.heads(&oid).unwrap(), want);
}

/// req: REQ-STORE-001
#[test]
fn objects_table_is_rebuildable_from_changes() {
    let key = DeviceKey::generate();
    let mut s = SqliteStore::open_in_memory().unwrap();
    let oid = ObjectId::random();
    let c1 = change(&key, oid, vec![], b"1");
    let c2 = change(&key, oid, vec![c1.change_id], b"2");
    s.put(c1).unwrap();
    s.put(c2).unwrap();
    s.put(change(&key, ObjectId::random(), vec![], b"other"))
        .unwrap();

    let before = s.objects().unwrap();
    assert_eq!(before.len(), 2);
    s.conn.execute("DELETE FROM objects", []).unwrap();
    assert!(s.objects().unwrap().is_empty());
    s.rebuild_objects().unwrap();
    assert_eq!(s.objects().unwrap(), before);
}

#[test]
fn rejects_newer_schema() {
    let path = temp_path("newer");
    {
        let c = Connection::open(&path).unwrap();
        c.execute_batch("PRAGMA user_version = 99;").unwrap();
    }
    assert!(SqliteStore::open(&path).is_err());
    let _ = std::fs::remove_file(&path);
}

/// req: REQ-STORE-002
#[test]
fn migration_steps_run_in_order_and_failures_roll_back() {
    fn add_column(c: &Connection) -> rusqlite::Result<()> {
        c.execute_batch("ALTER TABLE t ADD COLUMN extra TEXT;")
    }
    fn fill(c: &Connection) -> rusqlite::Result<()> {
        c.execute_batch("UPDATE t SET extra = 'x';")
    }
    fn broken(c: &Connection) -> rusqlite::Result<()> {
        c.execute_batch("ALTER TABLE t ADD COLUMN gone TEXT; SELECT * FROM missing;")
    }
    let version = |c: &Connection| -> i64 {
        c.query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap()
    };
    let db = || {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1); PRAGMA user_version = 3;",
        )
        .unwrap();
        c
    };
    let c = db();
    migrate(&c, 3, &[add_column, fill]).unwrap();
    assert_eq!(version(&c), 5);
    let extra: String = c
        .query_row("SELECT extra FROM t", [], |r| r.get(0))
        .unwrap();
    assert_eq!(extra, "x");
    // Starting one step in only runs the rest.
    let c = db();
    c.execute_batch("ALTER TABLE t ADD COLUMN extra TEXT; PRAGMA user_version = 4;")
        .unwrap();
    migrate(&c, 4, &[add_column, fill]).unwrap();
    assert_eq!(version(&c), 5);
    // A failing step keeps the last good version and undoes its own changes.
    let c = db();
    assert!(migrate(&c, 3, &[add_column, broken]).is_err());
    assert_eq!(version(&c), 4);
    assert!(c.prepare("SELECT gone FROM t").is_err());
}

/// req: REQ-STORE-002
#[test]
fn fixture_of_the_baseline_opens() {
    // Written by the first beta's code (`write_fixture` below); must keep opening forever.
    let dir = temp_path("fixture");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/schema-3.db"),
        &dir,
    )
    .unwrap();
    let s = SqliteStore::open(&dir).unwrap();
    let ids = s.all_ids().unwrap();
    assert_eq!(ids.len(), 2);
    for id in &ids {
        s.get(id).unwrap().unwrap().verify().unwrap();
    }
    let key = DeviceKey::from_secret_bytes(&[7; 32]);
    let oid = fixture_object();
    let history = s.history(&oid).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].author, kith_core::Signer::device_id(&key));
    assert_eq!(history[1].body.payload, b"second");
    assert_eq!(s.get_meta("note").unwrap(), Some(b"meta".to_vec()));
    assert_eq!(
        s.get_chunk(&[9; 32]).unwrap(),
        Some((Scope::local(), b"chunk".to_vec()))
    );
    let version: i64 = s
        .conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, SCHEMA_VERSION);
    drop(s);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", dir.display()));
    }
}

fn fixture_object() -> ObjectId {
    ObjectId::from_hex(&"ab".repeat(16)).unwrap()
}

/// Regenerates the fixture: `cargo test -p kith-store --features sqlite -- --ignored write_fixture`.
/// Only for a new schema version (keep the old file under its own name).
#[test]
#[ignore]
fn write_fixture() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/schema-3.db");
    let _ = std::fs::remove_file(path);
    let key = DeviceKey::from_secret_bytes(&[7; 32]);
    let mut s = SqliteStore::open(path).unwrap();
    let first = change(&key, fixture_object(), vec![], b"first");
    let second = change(&key, fixture_object(), vec![first.change_id], b"second");
    s.put(first).unwrap();
    s.put(second).unwrap();
    s.put_meta("note", b"meta").unwrap();
    s.put_chunk(&[9; 32], &Scope::local(), b"chunk").unwrap();
    s.conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")
        .unwrap();
}
