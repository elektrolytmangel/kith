//! SQLite backend (REQ-STORE-001).
//!
//! Changes are append-only rows. The `objects` table is a materialized view
//! derived from `changes` and can be rebuilt with [`SqliteStore::rebuild_objects`].

use std::path::Path;

use kith_core::{Change, ChangeId, DeviceId, ObjectId, ObjectType, Scope, UnsignedChange};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::{Store, StoreError};

/// 2: `meta` table (MLS state). 3: `scope` column (phase 6b; older envelopes
/// do not verify any more, so older non-empty databases are refused).
/// Current schema (`PRAGMA user_version`). Version 3 is the format baseline of the first beta
/// (ADR 0012): every later schema change adds a step to [`MIGRATIONS`] instead of editing it.
const SCHEMA_VERSION: i64 = FIRST_MIGRATABLE + MIGRATIONS.len() as i64;

/// Oldest schema this version can still read. Databases from before it come from an alpha.
const FIRST_MIGRATABLE: i64 = 3;

/// One schema upgrade step, run inside a transaction.
type Migration = fn(&Connection) -> rusqlite::Result<()>;

/// `MIGRATIONS[i]` upgrades schema `FIRST_MIGRATABLE + i` to the next one. Empty: nothing has
/// changed since the baseline. A new step needs a fixture database of the old version in
/// `tests/fixtures/` (see `fixture_of_the_baseline_opens`).
const MIGRATIONS: &[Migration] = &[];

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS changes (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    change_id    BLOB NOT NULL UNIQUE,
    object_id    BLOB NOT NULL,
    object_type  TEXT NOT NULL,
    scope        TEXT NOT NULL,
    author       BLOB NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    payload      BLOB NOT NULL,
    signature    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS changes_by_object ON changes(object_id, seq);
CREATE INDEX IF NOT EXISTS changes_by_scope ON changes(scope, seq);
CREATE TABLE IF NOT EXISTS change_parents (
    change_id BLOB NOT NULL,
    ord       INTEGER NOT NULL,
    parent_id BLOB NOT NULL,
    PRIMARY KEY (change_id, ord)
);
CREATE INDEX IF NOT EXISTS parents_by_parent ON change_parents(parent_id);
-- Materialized from `changes`; safe to drop and rebuild.
CREATE TABLE IF NOT EXISTS objects (
    object_id      BLOB PRIMARY KEY,
    object_type    TEXT NOT NULL,
    change_count   INTEGER NOT NULL,
    last_change_ms INTEGER NOT NULL
);
-- Encrypted file chunks (REQ-FILE-001), by SHA-256 of the ciphertext.
CREATE TABLE IF NOT EXISTS chunks (
    id    BLOB PRIMARY KEY,
    scope TEXT NOT NULL,
    data  BLOB NOT NULL
);
-- Small named blobs, e.g. the MLS group state (contains secrets).
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
";

fn backend(e: rusqlite::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Backend(format!("corrupt database: {what}"))
}

fn arr<const N: usize>(v: Vec<u8>, what: &str) -> Result<[u8; N], StoreError> {
    v.try_into().map_err(|_| corrupt(what))
}

/// Summary of one object from the materialized `objects` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSummary {
    /// Object ID.
    pub object_id: ObjectId,
    /// Type tag.
    pub object_type: ObjectType,
    /// Number of stored changes.
    pub change_count: u64,
    /// Timestamp of the newest change (author clock, informational).
    pub last_change_ms: u64,
}

/// SQLite-backed [`Store`].
pub struct SqliteStore {
    conn: Connection,
}

/// Run the steps from schema `from` up to the end of `steps`, each in its own transaction that
/// also records the new version, so a failed step leaves the database at the last good version.
fn migrate(conn: &Connection, from: i64, steps: &[Migration]) -> Result<(), StoreError> {
    let first =
        usize::try_from(from - FIRST_MIGRATABLE).map_err(|e| StoreError::Backend(e.to_string()))?;
    for (i, step) in steps.iter().enumerate().skip(first) {
        let next = FIRST_MIGRATABLE + i as i64 + 1;
        let tx = conn.unchecked_transaction().map_err(backend)?;
        step(&tx).map_err(backend)?;
        tx.execute_batch(&format!("PRAGMA user_version = {next};"))
            .map_err(backend)?;
        tx.commit().map_err(backend)?;
    }
    Ok(())
}

impl SqliteStore {
    /// Open (creating if needed) the database file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        owner_only(path).map_err(|e| StoreError::Backend(format!("{}: {e}", path.display())))?;
        Self::init(Connection::open(path).map_err(backend)?)
    }

    /// Private in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory().map_err(backend)?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        // WAL is not supported for in-memory databases; the pragma then reports "memory".
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))
            .map_err(backend)?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")
            .map_err(backend)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(backend)?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Backend(format!(
                "database schema version {version} is newer than supported {SCHEMA_VERSION}"
            )));
        }
        if (1..3).contains(&version) {
            // Changes from before scopes were signed (alpha) cannot be verified any more.
            let rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0))
                .map_err(backend)?;
            if rows > 0 {
                return Err(StoreError::Backend(format!(
                    "database from an older kith alpha (schema {version}); its changes cannot be read by this version"
                )));
            }
            conn.execute_batch(
                "DROP TABLE IF EXISTS changes; DROP TABLE IF EXISTS change_parents; DROP TABLE IF EXISTS objects;",
            )
            .map_err(backend)?;
        }
        if version >= FIRST_MIGRATABLE {
            migrate(&conn, version, MIGRATIONS)?;
        }
        conn.execute_batch(SCHEMA).map_err(backend)?;
        conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))
            .map_err(backend)?;
        Ok(Self { conn })
    }

    /// Recompute the `objects` table from `changes`.
    pub fn rebuild_objects(&mut self) -> Result<(), StoreError> {
        let tx = self.conn.transaction().map_err(backend)?;
        tx.execute("DELETE FROM objects", []).map_err(backend)?;
        tx.execute(
            "INSERT INTO objects (object_id, object_type, change_count, last_change_ms)
             SELECT object_id, MIN(object_type), COUNT(*), MAX(timestamp_ms)
             FROM changes GROUP BY object_id",
            [],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    /// All known objects, ordered by object ID.
    pub fn objects(&self) -> Result<Vec<ObjectSummary>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT object_id, object_type, change_count, last_change_ms
                 FROM objects ORDER BY object_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(backend)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ty, count, last) = row.map_err(backend)?;
            out.push(ObjectSummary {
                object_id: ObjectId(arr(id, "object_id")?),
                object_type: ObjectType::new(ty),
                change_count: count as u64,
                last_change_ms: last as u64,
            });
        }
        Ok(out)
    }

    fn parents_of(&self, id: &ChangeId) -> Result<Vec<ChangeId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT parent_id FROM change_parents WHERE change_id = ?1 ORDER BY ord",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([id.as_bytes().as_slice()], |r| r.get::<_, Vec<u8>>(0))
            .map_err(backend)?;
        rows.map(|r| Ok(ChangeId(arr(r.map_err(backend)?, "parent_id")?)))
            .collect()
    }

    fn change_from_row(&self, r: &Row<'_>) -> Result<Change, StoreError> {
        let change_id = ChangeId(arr(r.get(0).map_err(backend)?, "change_id")?);
        let ty: String = r.get(2).map_err(backend)?;
        let ts: i64 = r.get(4).map_err(backend)?;
        let scope: String = r.get(7).map_err(backend)?;
        let scope = Scope::parse(&scope).map_err(|_| corrupt("scope"))?;
        Ok(Change {
            change_id,
            body: UnsignedChange {
                scope,
                object_id: ObjectId(arr(r.get(1).map_err(backend)?, "object_id")?),
                object_type: ObjectType::new(ty),
                parents: self.parents_of(&change_id)?,
                timestamp_ms: ts as u64,
                payload: r.get(5).map_err(backend)?,
            },
            author: DeviceId(arr(r.get(3).map_err(backend)?, "author")?),
            signature: arr(r.get(6).map_err(backend)?, "signature")?,
        })
    }

    fn query_changes(&self, sql: &str, param: &[u8]) -> Result<Vec<Change>, StoreError> {
        let mut stmt = self.conn.prepare_cached(sql).map_err(backend)?;
        let mut rows = stmt.query([param]).map_err(backend)?;
        let mut out = Vec::new();
        while let Some(r) = rows.next().map_err(backend)? {
            out.push(self.change_from_row(r)?);
        }
        Ok(out)
    }
}

const SELECT: &str = "SELECT change_id, object_id, object_type, author, timestamp_ms, payload, signature, scope FROM changes";

impl Store for SqliteStore {
    fn put(&mut self, change: Change) -> Result<bool, StoreError> {
        let tx = self.conn.transaction().map_err(backend)?;
        let id = change.change_id;
        let b = &change.body;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO changes
                 (change_id, object_id, object_type, author, timestamp_ms, payload, signature, scope)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.as_bytes().as_slice(),
                    b.object_id.as_bytes().as_slice(),
                    b.object_type.as_str(),
                    change.author.as_bytes().as_slice(),
                    b.timestamp_ms as i64,
                    b.payload,
                    change.signature.as_slice(),
                    b.scope.as_str(),
                ],
            )
            .map_err(backend)?;
        if inserted == 0 {
            return Ok(false);
        }
        for (ord, p) in b.parents.iter().enumerate() {
            tx.execute(
                "INSERT INTO change_parents (change_id, ord, parent_id) VALUES (?1, ?2, ?3)",
                params![
                    id.as_bytes().as_slice(),
                    ord as i64,
                    p.as_bytes().as_slice()
                ],
            )
            .map_err(backend)?;
        }
        tx.execute(
            "INSERT INTO objects (object_id, object_type, change_count, last_change_ms)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(object_id) DO UPDATE SET
                 change_count = change_count + 1,
                 last_change_ms = MAX(last_change_ms, excluded.last_change_ms)",
            params![
                b.object_id.as_bytes().as_slice(),
                b.object_type.as_str(),
                b.timestamp_ms as i64
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)?;
        Ok(true)
    }

    fn get(&self, id: &ChangeId) -> Result<Option<Change>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached(&format!("{SELECT} WHERE change_id = ?1"))
            .map_err(backend)?;
        let mut rows = stmt.query([id.as_bytes().as_slice()]).map_err(backend)?;
        match rows.next().map_err(backend)? {
            Some(r) => Ok(Some(self.change_from_row(r)?)),
            None => Ok(None),
        }
    }

    fn contains(&self, id: &ChangeId) -> Result<bool, StoreError> {
        self.conn
            .query_row(
                "SELECT 1 FROM changes WHERE change_id = ?1",
                [id.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .map_err(backend)
    }

    fn history(&self, object: &ObjectId) -> Result<Vec<Change>, StoreError> {
        self.query_changes(
            &format!("{SELECT} WHERE object_id = ?1 ORDER BY seq"),
            object.as_bytes(),
        )
    }

    fn all_ids(&self) -> Result<Vec<ChangeId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT change_id FROM changes ORDER BY seq")
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(backend)?;
        rows.map(|r| Ok(ChangeId(arr(r.map_err(backend)?, "change_id")?)))
            .collect()
    }

    fn scope_ids(&self, scope: &Scope) -> Result<Vec<ChangeId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT change_id FROM changes WHERE scope = ?1 ORDER BY seq")
            .map_err(backend)?;
        let rows = stmt
            .query_map([scope.as_str()], |r| r.get::<_, Vec<u8>>(0))
            .map_err(backend)?;
        rows.map(|r| Ok(ChangeId(arr(r.map_err(backend)?, "change_id")?)))
            .collect()
    }

    fn heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, StoreError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                // Only children in the same object count, as in `Store::heads`.
                "SELECT c.change_id FROM changes c
                 WHERE c.object_id = ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM change_parents p JOIN changes k ON k.change_id = p.change_id
                     WHERE p.parent_id = c.change_id AND k.object_id = ?1)
                 ORDER BY c.change_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([object.as_bytes().as_slice()], |r| r.get::<_, Vec<u8>>(0))
            .map_err(backend)?;
        rows.map(|r| Ok(ChangeId(arr(r.map_err(backend)?, "change_id")?)))
            .collect()
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")
            .map_err(backend)?
            .query_row([key], |r| r.get(0))
            .optional()
            .map_err(backend)
    }

    fn delete(&mut self, ids: &[ChangeId]) -> Result<(), StoreError> {
        let tx = self.conn.transaction().map_err(backend)?;
        for id in ids {
            let id = id.as_bytes().as_slice();
            let object: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT object_id FROM changes WHERE change_id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(backend)?;
            let Some(object) = object else { continue };
            tx.execute("DELETE FROM changes WHERE change_id = ?1", [id])
                .map_err(backend)?;
            tx.execute("DELETE FROM change_parents WHERE change_id = ?1", [id])
                .map_err(backend)?;
            tx.execute(
                "UPDATE objects SET change_count = change_count - 1 WHERE object_id = ?1",
                [object.as_slice()],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)
    }

    fn delete_chunk(&mut self, id: &[u8; 32]) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM chunks WHERE id = ?1", [id.as_slice()])
            .map_err(backend)?;
        Ok(())
    }

    fn put_chunk(&mut self, id: &[u8; 32], scope: &Scope, data: &[u8]) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO chunks (id, scope, data) VALUES (?1, ?2, ?3)",
                params![id.as_slice(), scope.as_str(), data],
            )
            .map_err(backend)?;
        Ok(())
    }

    fn get_chunk(&self, id: &[u8; 32]) -> Result<Option<(Scope, Vec<u8>)>, StoreError> {
        let row: Option<(String, Vec<u8>)> = self
            .conn
            .prepare_cached("SELECT scope, data FROM chunks WHERE id = ?1")
            .map_err(backend)?
            .query_row([id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .map_err(backend)?;
        row.map(|(s, d)| Ok((Scope::parse(&s).map_err(|_| corrupt("chunk scope"))?, d)))
            .transpose()
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        // `synchronous = NORMAL` in WAL mode can lose the last commit on power loss.
        // For the MLS state that could mean reusing an encryption key, so this write
        // is synced fully.
        self.conn
            .execute_batch("PRAGMA synchronous = FULL;")
            .map_err(backend)?;
        let res = self
            .conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(backend);
        self.conn
            .execute_batch("PRAGMA synchronous = NORMAL;")
            .map_err(backend)?;
        res.map(|_| ())
    }
}

/// Create the database file readable by its owner only, and take group/other
/// access away from an existing one and its WAL files (REQ-STORE-003). SQLite
/// creates the WAL files with the database file's permissions. Other platforms
/// keep their defaults (app sandboxes, Windows ACLs of the user's profile).
#[cfg(unix)]
fn owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Ok(());
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            for suffix in ["", "-wal", "-shm"] {
                let mut p = path.as_os_str().to_owned();
                p.push(suffix);
                let Ok(meta) = std::fs::metadata(&p) else {
                    continue;
                };
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode & 0o700))?;
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
fn owner_only(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
