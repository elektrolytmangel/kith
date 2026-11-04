# 0009: Encrypted files in verifiable chunks

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-FILE-001, REQ-FILE-002

## Context

Large files must not go through the change flow as one blob: a change body is
capped at 1 MiB, every member would have to download every file, and MLS would
re-encrypt it per message. The design doc sketches encrypted chunks plus a
reference object and fetching from any peer.

## Decision

- **Encryption**: a fresh random 32-byte key per file; chunks of 256 KiB sealed
  with **XChaCha20-Poly1305**. The nonce is the chunk index (the key is used for this
  file only), and the AAD binds index and version (`kith/file-chunk/v1`), so chunks
  cannot be reordered. The **chunk ID is SHA-256 of the ciphertext**, so any peer
  can store, serve and verify chunks without the key.
- **Reference**: a `kith.file` object (name, MIME, size, key, chunk IDs) is an
  ordinary change: signed, MLS-encrypted, scoped, permission-checked. The chunk
  count must match the size.
- **Storage**: `Store::put_chunk` / `get_chunk` (SQLite table `chunks`, IndexedDB
  store `chunks`, memory), each chunk tagged with its file's scope.
- **Fetching** (REQ-FILE-002): `ChunkWant { ids }` is encrypted for the file's scope.
  For an org file it goes as a sync request, so the relay picks a peer and prefers
  the always-on client. For a subgroup file it goes direct to a member. The peer
  answers with `Chunks`, split under the frame limit, and `ChunkMissing` for what it
  lacks. A peer only serves chunks whose scope matches the scope the request was
  encrypted for. Arriving chunks are stored only if wanted and only if their hash
  matches. `FileChunks { ready }` reports finished files.
- **Lazy by default**, eager on request (`set_fetch_files`). The always-on client
  fetches eagerly, so it holds every file.

## Consequences

- Files of any size, readable only by members of their scope; peers cannot tamper
  with chunks.
- Fetch requests are answered by one peer. If it lacks chunks, the app retries
  later (`ChunksMissing`). There is no fan-out to several peers and no resumable
  transfer state beyond the missing list (REQ-SYNC-005, phase 8).
- Chunks travel through the relay (no peer-to-peer path yet). On the web all chunks
  are kept in memory (the `Store` API is synchronous).
- A file is immutable: a new version is a new `kith.file` object.

## Alternatives considered

- **Chunks as changes**: every member would store every chunk, and the relay frame
  limit would apply to each change.
- **Random nonce per chunk**: unnecessary with a one-time key; the index nonce also
  makes reordering detectable.
- **Peer-to-peer transfer (Iroh/WebRTC)**: faster for big files, much more surface;
  later.
