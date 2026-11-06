//! Encrypted large files (phase 7b, REQ-FILE-001/002, ADR 0009).
//!
//! A file becomes encrypted chunks in the store plus one `kith.file` object (its
//! name, MIME type, size, key and chunk IDs) that syncs like any change. Chunks are
//! fetched on demand (`fetch_file_frames`) or eagerly (`set_fetch_files`) from any
//! peer of the file's scope, and verified by hash on arrival.

use kith_crypto::files::{CHUNK_SIZE, ChunkId, chunk_id, decrypt_chunk, encrypt_file};

use crate::*;

/// Object type of file references.
pub const FILE_TYPE: &str = "kith.file";

/// What a `kith.file` object says about a file.
#[derive(Clone, PartialEq, Eq)]
pub struct FileRef {
    /// File name (informational).
    pub name: String,
    /// MIME type (informational).
    pub mime: String,
    /// Plaintext size in bytes.
    pub size: u64,
    /// The file key (secret; travels only inside the encrypted change flow).
    pub key: [u8; 32],
    /// Chunk IDs in order.
    pub chunks: Vec<ChunkId>,
}

impl std::fmt::Debug for FileRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRef")
            .field("name", &self.name)
            .field("mime", &self.mime)
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

const VERSION: u8 = 1;

impl FileRef {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = vec![VERSION];
        for s in [&self.name, &self.mime] {
            w.extend_from_slice(&(s.len().min(u16::MAX as usize) as u16).to_be_bytes());
            w.extend_from_slice(&s.as_bytes()[..s.len().min(u16::MAX as usize)]);
        }
        w.extend_from_slice(&self.size.to_be_bytes());
        w.extend_from_slice(&self.key);
        w.extend_from_slice(&(self.chunks.len() as u32).to_be_bytes());
        for c in &self.chunks {
            w.extend_from_slice(c);
        }
        w
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Bytes(b);
        if r.take(1)?[0] != VERSION {
            return None;
        }
        let name = r.text()?;
        let mime = r.text()?;
        let size = u64::from_be_bytes(r.take(8)?.try_into().ok()?);
        let key: [u8; 32] = r.take(32)?.try_into().ok()?;
        let n = u32::from_be_bytes(r.take(4)?.try_into().ok()?) as usize;
        // The chunk count must match the size: no file "claims" chunks it cannot have.
        if n != usize::try_from(size).ok()?.div_ceil(CHUNK_SIZE) || r.0.len() != n * 32 {
            return None;
        }
        let chunks =
            r.0.chunks(32)
                .map(|c| c.try_into().expect("32 bytes"))
                .collect();
        Some(Self {
            name,
            mime,
            size,
            key,
            chunks,
        })
    }
}

struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (h, t) = self.0.split_at_checked(n)?;
        self.0 = t;
        Some(h)
    }
    fn text(&mut self) -> Option<String> {
        let n = u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

/// What `Client::file_info` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileInfo {
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Size in bytes.
    pub size: u64,
    /// Number of chunks.
    pub chunks: usize,
    /// Chunks not stored on this device yet (0: `read_file` works).
    pub missing: usize,
}

impl<S: Store, K: Signer> Client<S, K> {
    /// Store a file in the default scope (see [`Client::create`]): encrypted chunks
    /// locally, and a `kith.file` object to broadcast like any change. Peers fetch
    /// the chunks from any device that has them.
    pub fn add_file(&mut self, name: &str, mime: &str, data: &[u8]) -> Result<Change, ClientError> {
        let scope = self.default_scope()?;
        self.add_file_in(scope, name, mime, data)
    }

    /// [`Self::add_file`] in `scope` (an org, `org/subgroup`, or `local`).
    pub fn add_file_in(
        &mut self,
        scope: Scope,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<Change, ClientError> {
        self.check_scope(&scope)?;
        let f = encrypt_file(data);
        for (id, ct) in &f.chunks {
            self.store.put_chunk(id, &scope, ct)?;
        }
        let r = FileRef {
            name: name.into(),
            mime: mime.into(),
            size: f.size,
            key: f.key,
            chunks: f.chunks.iter().map(|(id, _)| *id).collect(),
        };
        self.create_in(scope, ObjectType::new(FILE_TYPE), r.encode())
    }

    /// The file reference of a `kith.file` object: its newest version.
    pub fn file_ref(&self, object: &ObjectId) -> Result<(Scope, FileRef), ClientError> {
        let hist = self.history(object)?;
        let first = hist.first().ok_or(ClientError::UnknownObject(*object))?;
        if first.body.object_type.as_str() != FILE_TYPE {
            return Err(ClientError::InvalidDocument("not a file".into()));
        }
        // The newest change that is a file reference; one with another payload (from a
        // buggy or hostile editor) must not hide the file.
        let r = hist
            .iter()
            .filter_map(|c| {
                Some((
                    (c.body.timestamp_ms, c.change_id),
                    FileRef::decode(&c.body.payload)?,
                ))
            })
            .max_by_key(|(k, _)| *k)
            .map(|(_, r)| r)
            .ok_or_else(|| ClientError::InvalidDocument("malformed file reference".into()))?;
        Ok((first.body.scope.clone(), r))
    }

    /// Replace the content of a file object with a new version (a new `kith.file`
    /// change; REQ-DATA-005 can later drop the old versions and their chunks). Send
    /// the returned change like any other.
    pub fn update_file(
        &mut self,
        object: ObjectId,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<Change, ClientError> {
        let (ty, scope) = self.object_meta(&object)?;
        if ty.as_str() != FILE_TYPE {
            return Err(ClientError::InvalidDocument("not a file".into()));
        }
        let f = encrypt_file(data);
        for (id, ct) in &f.chunks {
            self.store.put_chunk(id, &scope, ct)?;
        }
        let r = FileRef {
            name: name.into(),
            mime: mime.into(),
            size: f.size,
            key: f.key,
            chunks: f.chunks.iter().map(|(id, _)| *id).collect(),
        };
        self.edit(object, r.encode())
    }

    /// Chunks of a file this device does not have yet.
    pub fn missing_chunks(&self, object: &ObjectId) -> Result<Vec<ChunkId>, ClientError> {
        let (_, r) = self.file_ref(object)?;
        let mut out = vec![];
        for id in &r.chunks {
            if self.store.get_chunk(id)?.is_none() {
                out.push(*id);
            }
        }
        Ok(out)
    }

    /// Name, type, size and how many chunks are still missing.
    pub fn file_info(&self, object: &ObjectId) -> Result<FileInfo, ClientError> {
        let (_, r) = self.file_ref(object)?;
        Ok(FileInfo {
            missing: self.missing_chunks(object)?.len(),
            chunks: r.chunks.len(),
            name: r.name,
            mime: r.mime,
            size: r.size,
        })
    }

    /// The file's contents, if all chunks are here ([`ClientError::FileIncomplete`]
    /// otherwise: fetch them first).
    pub fn read_file(&self, object: &ObjectId) -> Result<Vec<u8>, ClientError> {
        let (_, r) = self.file_ref(object)?;
        let mut out = Vec::with_capacity(r.size as usize);
        for (i, id) in r.chunks.iter().enumerate() {
            let Some((_, ct)) = self.store.get_chunk(id)? else {
                return Err(ClientError::FileIncomplete(
                    self.missing_chunks(object)?.len(),
                ));
            };
            out.extend(
                decrypt_chunk(&r.key, i, &ct)
                    .map_err(|e| ClientError::InvalidDocument(e.to_string()))?,
            );
        }
        out.truncate(r.size as usize);
        Ok(out)
    }

    /// Fetch this device's missing chunks of a file through `org`'s relay
    /// (REQ-FILE-002). For an org file the relay picks a peer (the always-on client
    /// first); for a subgroup file a subgroup member is asked. `Event::FileReady`
    /// follows once all chunks are here; `Event::ChunksMissing` if the peer lacks some
    /// (try again later). Empty if nothing is missing.
    pub fn fetch_file_frames(
        &mut self,
        org: &str,
        object: &ObjectId,
    ) -> Result<Vec<Frame>, ClientError> {
        let (scope, _) = self.file_ref(object)?;
        if !in_org(org, scope.as_str()) {
            return Err(ClientError::Forbidden(format!(
                "file of scope {scope}, not org {org}"
            )));
        }
        let missing = self.missing_chunks(object)?;
        if missing.is_empty() {
            return Ok(vec![]);
        }
        self.wanted_chunks
            .entry(*object)
            .or_default()
            .extend(missing.iter().copied());
        let mut frames = vec![];
        for inner in sync::chunk_want_bodies(&missing) {
            let body = self.app_body(scope.as_str(), &inner)?;
            frames.push(if scope.as_str() == org {
                Frame::SyncRequest {
                    org: org.into(),
                    body,
                }
            } else {
                let peer = self
                    .subgroup_peer(org, scope.as_str())
                    .ok_or_else(|| ClientError::Forbidden("no other subgroup member".into()))?;
                direct(org, &peer.to_hex(), body)
            });
        }
        self.save_groups()?;
        Ok(frames)
    }

    /// Fetch every new file's chunks as soon as its `kith.file` object arrives
    /// (eager mode, e.g. on always-on clients). Default: off (lazy).
    pub fn set_fetch_files(&mut self, eager: bool) {
        self.fetch_files = eager;
    }

    /// Frames to fetch a newly received file in eager mode.
    pub(crate) fn eager_fetch(
        &mut self,
        org: &str,
        change: &Change,
    ) -> Result<Vec<Frame>, ClientError> {
        if !self.fetch_files || change.body.object_type.as_str() != FILE_TYPE {
            return Ok(vec![]);
        }
        self.fetch_file_frames(org, &change.body.object_id)
    }

    /// Answer a peer's `ChunkWant` with the chunks of `scope` we have.
    pub(crate) fn serve_chunks(
        &mut self,
        org: &str,
        scope: &str,
        to: &str,
        ids: &[ChunkId],
    ) -> Result<(Vec<Frame>, usize, usize), ClientError> {
        let (mut found, mut missing) = (vec![], vec![]);
        for id in ids {
            match self.store.get_chunk(id)? {
                // Only chunks of files in the scope the request was encrypted for.
                Some((s, data)) if s.as_str() == scope => found.push((*id, data)),
                _ => missing.push(*id),
            }
        }
        let mut frames = vec![];
        for inner in sync::chunks_bodies(&found) {
            frames.push(direct(org, to, self.app_body(scope, &inner)?));
        }
        if !missing.is_empty() {
            frames.push(direct(
                org,
                to,
                self.app_body(scope, &sync::chunk_missing_body(&missing))?,
            ));
        }
        Ok((frames, found.len(), missing.len()))
    }

    /// Store chunks that arrived for files we are fetching; returns how many were
    /// stored and which files are now complete.
    pub(crate) fn absorb_chunks(
        &mut self,
        scope: &str,
        chunks: Vec<(ChunkId, Vec<u8>)>,
    ) -> Result<(usize, Vec<ObjectId>), ClientError> {
        let scope = org_scope(scope)?;
        let mut stored = 0;
        for (id, data) in chunks {
            let wanted = self.wanted_chunks.values().any(|w| w.contains(&id));
            if !wanted || chunk_id(&data) != id {
                continue;
            }
            self.store.put_chunk(&id, &scope, &data)?;
            stored += 1;
            for w in self.wanted_chunks.values_mut() {
                w.remove(&id);
            }
        }
        let done: Vec<ObjectId> = self
            .wanted_chunks
            .iter()
            .filter(|(_, w)| w.is_empty())
            .map(|(o, _)| *o)
            .collect();
        for o in &done {
            self.wanted_chunks.remove(o);
            self.asked_author.remove(o);
        }
        Ok((stored, done))
    }

    /// A peer lacked chunks we want: ask each affected file's author directly (once
    /// per file). The author made the file, so it has every chunk, unless it lost them.
    pub(crate) fn ask_authors(
        &mut self,
        org: &str,
        scope: &str,
        peer: &str,
        ids: &[ChunkId],
    ) -> Result<Vec<Frame>, ClientError> {
        let me = self.device_id().to_hex();
        let affected: Vec<ObjectId> = self
            .wanted_chunks
            .iter()
            .filter(|(o, w)| !self.asked_author.contains(*o) && ids.iter().any(|i| w.contains(i)))
            .map(|(o, _)| *o)
            .collect();
        let mut frames = vec![];
        for object in affected {
            let author = match self
                .store
                .history(&object)?
                .iter()
                .find(|c| c.is_creation())
            {
                Some(c) if c.body.scope.as_str() == scope => c.author.to_hex(),
                _ => continue,
            };
            self.asked_author.insert(object);
            if author == me || author == peer {
                continue;
            }
            let want: Vec<ChunkId> = self.wanted_chunks[&object]
                .iter()
                .filter(|i| ids.contains(i))
                .copied()
                .collect();
            for inner in sync::chunk_want_bodies(&want) {
                frames.push(direct(org, &author, self.app_body(scope, &inner)?));
            }
        }
        Ok(frames)
    }

    /// Another online-or-not member of subgroup `group` to ask (its owner first).
    pub(crate) fn subgroup_peer(&self, org: &str, group: &str) -> Option<DeviceId> {
        let me = self.device_id();
        self.subgroup_owner(org, group)
            .filter(|o| *o != me)
            .or_else(|| {
                self.groups
                    .members(group)
                    .ok()?
                    .into_iter()
                    .find(|d| *d != me)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_refs_roundtrip_and_reject_garbage() {
        let r = FileRef {
            name: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            size: (CHUNK_SIZE + 1) as u64,
            key: [5; 32],
            chunks: vec![[1; 32], [2; 32]],
        };
        assert_eq!(FileRef::decode(&r.encode()), Some(r.clone()));
        let b = r.encode();
        for len in 0..b.len() {
            assert!(FileRef::decode(&b[..len]).is_none(), "len {len}");
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(FileRef::decode(&extra).is_none());
        let mut wrong_count = r;
        wrong_count.chunks.push([3; 32]);
        assert!(FileRef::decode(&wrong_count.encode()).is_none());
        assert!(!format!("{:?}", FileRef::decode(&b).unwrap()).contains("key"));
    }
}
