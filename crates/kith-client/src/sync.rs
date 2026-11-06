//! Relay bodies, sans-IO: the outer MLS layer (REQ-ENC-001..004) and the
//! data messages inside it (REQ-SYNC-001..004).
//!
//! **Outer** (what the relay sees), `[kind][payload]`, see [`Outer`]: an MLS
//! application message, a commit, a Welcome, a KeyPackage, or the group catch-up
//! messages (commit request, commits, re-add needed). Only the MLS messages'
//! clear headers (group, epoch, content type) and these kinds are visible.
//!
//! **Inner** (plaintext of an MLS application message), `[kind][payload]`:
//!
//! - `Change`: one encoded change (live updates, REQ-SYNC-004).
//! - `Query` / `Reply`: rounds of range-based set reconciliation (Negentropy,
//!   `kith_sync`). The first `Query` is sent as a `SyncRequest`, which the relay
//!   hands to one online peer; the rest go `Direct`. The requester ends up knowing
//!   what each side lacks (REQ-SYNC-001..003).
//! - `Offer`: changes the receiver lacks, plus IDs the sender wants back. The
//!   requester sends one when reconciliation is done; the partner answers with an
//!   `Offer` carrying what was wanted.

use kith_core::{Change, ChangeId, DeviceId};

const KIND_CHANGE: u8 = 1;
// 2 was the full-ID `Have` before range-based reconciliation.
const KIND_OFFER: u8 = 3;
const KIND_QUERY: u8 = 4;
const KIND_REPLY: u8 = 5;
const KIND_CHUNK_WANT: u8 = 6;
const KIND_CHUNKS: u8 = 7;
const KIND_CHUNK_MISSING: u8 = 8;

/// Stay well below the frame limit: the body is JSON-encoded by the relay protocol
/// only after this check, and one oversized change must not block the others.
const MAX_OFFER_BYTES: usize = 512 * 1024;

const OUTER_APP: u8 = 0x10;
const OUTER_COMMIT: u8 = 0x11;
const OUTER_WELCOME: u8 = 0x12;
const OUTER_KEY_PACKAGE: u8 = 0x13;
const OUTER_COMMIT_REQUEST: u8 = 0x14;
const OUTER_COMMITS: u8 = 0x15;
const OUTER_READD_NEEDED: u8 = 0x16;
const OUTER_CLAIM: u8 = 0x17;
const OUTER_CERT: u8 = 0x18;
const OUTER_CLAIM_NONCE: u8 = 0x19;

/// A parsed relay body (outer layer).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outer {
    /// MLS application message; plaintext is an inner [`Message`].
    App(Vec<u8>),
    /// MLS commit, broadcast to the group.
    Commit(Vec<u8>),
    /// MLS Welcome, direct to a new member, with its membership certificate chain
    /// (hex; empty for a re-add, which keeps the old one).
    Welcome {
        /// The MLS Welcome.
        welcome: Vec<u8>,
        /// `CertChain::to_hex`, or empty.
        chain: String,
    },
    /// An invite claim (REQ-INV-002): token, proof of the secret, KeyPackage.
    Claim {
        /// The invite's token.
        token: [u8; 16],
        /// `Invite::claim_proof` over the KeyPackage.
        proof: [u8; 32],
        /// The claimer's MLS KeyPackage.
        key_package: Vec<u8>,
    },
    /// The admin's answer to a valid claim, direct to the claimer: a random nonce
    /// both sides mix into the short code, signed by the admin over
    /// `Invite::nonce_signed_bytes`, with the admin's certificate chain (hex).
    ClaimNonce {
        /// The invite's token.
        token: [u8; 16],
        /// Random, chosen after the claim arrived.
        nonce: [u8; 32],
        /// The admin's Ed25519 signature.
        signature: [u8; 64],
        /// `CertChain::to_hex` of the admin.
        chain: String,
    },
    /// A new membership certificate chain for the receiver (hex), e.g. admin rights.
    Cert(String),
    /// KeyPackage of a device that wants to be added (or re-added) to `group` (the
    /// org, or `org/subgroup`), direct to a member.
    KeyPackage {
        /// Group key.
        group: String,
        /// The KeyPackage.
        key_package: Vec<u8>,
    },
    /// "I am at this epoch of `group`, send me the commits since."
    CommitRequest {
        /// Group key.
        group: String,
        /// Our epoch.
        epoch: u64,
    },
    /// Commits of `group` in epoch order with their committers, answering a
    /// `CommitRequest` (or showing a peer on a losing fork branch the winning commit).
    Commits {
        /// Group key.
        group: String,
        /// (committer, commit).
        commits: Vec<(DeviceId, Vec<u8>)>,
    },
    /// "My commit log for `group` does not reach back to your epoch; send a
    /// KeyPackage to be re-added."
    ReaddNeeded {
        /// Group key.
        group: String,
    },
}

pub(crate) fn outer_body(msg: &Outer) -> Vec<u8> {
    let (kind, payload): (u8, &[u8]) = match msg {
        Outer::App(b) => (OUTER_APP, b),
        Outer::Commit(b) => (OUTER_COMMIT, b),
        Outer::Welcome { welcome, chain } => {
            let mut out = vec![OUTER_WELCOME];
            out.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
            out.extend_from_slice(welcome);
            out.extend_from_slice(chain.as_bytes());
            return out;
        }
        Outer::Claim {
            token,
            proof,
            key_package,
        } => {
            let mut out = vec![OUTER_CLAIM];
            out.extend_from_slice(token);
            out.extend_from_slice(proof);
            out.extend_from_slice(key_package);
            return out;
        }
        Outer::ClaimNonce {
            token,
            nonce,
            signature,
            chain,
        } => {
            let mut out = vec![OUTER_CLAIM_NONCE];
            out.extend_from_slice(token);
            out.extend_from_slice(nonce);
            out.extend_from_slice(signature);
            out.extend_from_slice(chain.as_bytes());
            return out;
        }
        Outer::Cert(chain) => (OUTER_CERT, chain.as_bytes()),
        Outer::KeyPackage { group, key_package } => {
            let mut out = vec![OUTER_KEY_PACKAGE];
            put_group(&mut out, group);
            out.extend_from_slice(key_package);
            return out;
        }
        Outer::CommitRequest { group, epoch } => {
            let mut out = vec![OUTER_COMMIT_REQUEST];
            put_group(&mut out, group);
            out.extend_from_slice(&epoch.to_be_bytes());
            return out;
        }
        Outer::Commits { group, commits } => {
            let mut out = vec![OUTER_COMMITS];
            put_group(&mut out, group);
            out.extend_from_slice(&(commits.len() as u32).to_be_bytes());
            for (committer, c) in commits {
                out.extend_from_slice(&committer.0);
                out.extend_from_slice(&(c.len() as u32).to_be_bytes());
                out.extend_from_slice(c);
            }
            return out;
        }
        Outer::ReaddNeeded { group } => {
            let mut out = vec![OUTER_READD_NEEDED];
            put_group(&mut out, group);
            return out;
        }
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

fn put_group(out: &mut Vec<u8>, group: &str) {
    out.push(group.len().min(255) as u8);
    out.extend_from_slice(&group.as_bytes()[..group.len().min(255)]);
}

/// `Commits` bodies of `group` for `commits`, split to stay under the frame limit, in order.
pub(crate) fn commits_bodies(
    group: &str,
    commits: Vec<kith_crypto::group::LoggedCommit>,
) -> Vec<Vec<u8>> {
    let mut bodies = vec![];
    let mut batch = vec![];
    let mut size = 0;
    let body = |commits| {
        outer_body(&Outer::Commits {
            group: group.into(),
            commits,
        })
    };
    for c in commits {
        if size + c.commit.len() > MAX_OFFER_BYTES && !batch.is_empty() {
            bodies.push(body(std::mem::take(&mut batch)));
            size = 0;
        }
        size += c.commit.len();
        batch.push((c.committer, c.commit));
    }
    if !batch.is_empty() {
        bodies.push(body(batch));
    }
    bodies
}

pub(crate) fn parse_outer(body: &[u8]) -> Result<Outer, String> {
    let (&kind, rest) = body.split_first().ok_or("empty body")?;
    let mut r = Reader(rest);
    let msg = match kind {
        OUTER_APP => Outer::App(rest.to_vec()),
        OUTER_COMMIT => Outer::Commit(rest.to_vec()),
        OUTER_WELCOME => {
            let n = r.u32()? as usize;
            let welcome = r.take(n)?.to_vec();
            let chain = String::from_utf8(std::mem::take(&mut r.0).to_vec())
                .map_err(|_| "certificate chain is not text")?;
            if welcome.is_empty() {
                return Err("empty welcome".into());
            }
            Outer::Welcome { welcome, chain }
        }
        OUTER_CLAIM => {
            let token = r.take(16)?.try_into().expect("16 bytes");
            let proof = r.take(32)?.try_into().expect("32 bytes");
            let key_package = std::mem::take(&mut r.0).to_vec();
            if key_package.is_empty() {
                return Err("empty key package".into());
            }
            Outer::Claim {
                token,
                proof,
                key_package,
            }
        }
        OUTER_CLAIM_NONCE => {
            let token = r.take(16)?.try_into().expect("16 bytes");
            let nonce = r.take(32)?.try_into().expect("32 bytes");
            let signature = r.take(64)?.try_into().expect("64 bytes");
            let chain = String::from_utf8(std::mem::take(&mut r.0).to_vec())
                .map_err(|_| "certificate chain is not text")?;
            Outer::ClaimNonce {
                token,
                nonce,
                signature,
                chain,
            }
        }
        OUTER_CERT => Outer::Cert(
            String::from_utf8(rest.to_vec()).map_err(|_| "certificate chain is not text")?,
        ),
        OUTER_KEY_PACKAGE => {
            let group = r.group()?;
            let key_package = std::mem::take(&mut r.0).to_vec();
            if key_package.is_empty() {
                return Err("empty key package".into());
            }
            Outer::KeyPackage { group, key_package }
        }
        OUTER_COMMIT_REQUEST => {
            let group = r.group()?;
            Outer::CommitRequest {
                group,
                epoch: u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes")),
            }
        }
        OUTER_COMMITS => {
            let group = r.group()?;
            let n = r.u32()? as usize;
            if n > r.0.len() / 36 {
                return Err("commit count exceeds data".into());
            }
            let mut cs = Vec::with_capacity(n);
            for _ in 0..n {
                let committer = DeviceId(r.take(32)?.try_into().expect("32 bytes"));
                let len = r.u32()? as usize;
                cs.push((committer, r.take(len)?.to_vec()));
            }
            Outer::Commits { group, commits: cs }
        }
        OUTER_READD_NEEDED => Outer::ReaddNeeded { group: r.group()? },
        // 1..=3 were plaintext data bodies before MLS (hard break, ADR 0004).
        1..=3 => return Err("unencrypted body refused".into()),
        other => return Err(format!("unknown body kind {other}")),
    };
    let fixed = matches!(
        kind,
        OUTER_COMMIT_REQUEST
            | OUTER_COMMITS
            | OUTER_READD_NEEDED
            | OUTER_WELCOME
            | OUTER_CLAIM
            | OUTER_CLAIM_NONCE
            | OUTER_KEY_PACKAGE
    );
    if fixed && !r.0.is_empty() {
        return Err("trailing bytes".into());
    }
    if !fixed && rest.is_empty() {
        return Err("empty payload".into());
    }
    Ok(msg)
}

/// A parsed inner (decrypted) message.
pub(crate) enum Message {
    Change(Change),
    /// A reconciliation round from the requester.
    Query(Vec<u8>),
    /// The partner's answer to a `Query`.
    Reply(Vec<u8>),
    /// "Send me these file chunks" (REQ-FILE-002).
    ChunkWant(Vec<[u8; 32]>),
    /// File chunks: `(id, ciphertext)`.
    Chunks(Vec<([u8; 32], Vec<u8>)>),
    /// "I do not have these chunks."
    ChunkMissing(Vec<[u8; 32]>),
    Offer {
        want: Vec<ChangeId>,
        /// Encoded changes, decoded one by one so a bad one cannot hide the rest.
        changes: Vec<Vec<u8>>,
    },
}

pub(crate) fn change_body(change: &Change) -> Vec<u8> {
    let mut out = vec![KIND_CHANGE];
    out.extend_from_slice(&kith_store::codec::encode_change(change));
    out
}

pub(crate) fn query_body(msg: &[u8]) -> Vec<u8> {
    let mut out = vec![KIND_QUERY];
    out.extend_from_slice(msg);
    out
}

fn ids_body(kind: u8, ids: &[[u8; 32]]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    out
}

/// `ChunkWant` bodies for `ids`, split to stay under the size limit.
pub(crate) fn chunk_want_bodies(ids: &[[u8; 32]]) -> Vec<Vec<u8>> {
    ids.chunks(MAX_WANT_IDS)
        .map(|c| ids_body(KIND_CHUNK_WANT, c))
        .collect()
}

pub(crate) fn chunk_missing_body(ids: &[[u8; 32]]) -> Vec<u8> {
    ids_body(KIND_CHUNK_MISSING, ids)
}

/// `Chunks` bodies, split to stay under the size limit (a chunk is at most 256 KiB).
pub(crate) fn chunks_bodies(chunks: &[([u8; 32], Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut bodies = vec![];
    let mut batch: Vec<&([u8; 32], Vec<u8>)> = vec![];
    let mut size = 0;
    let flush = |batch: &mut Vec<&([u8; 32], Vec<u8>)>, bodies: &mut Vec<Vec<u8>>| {
        let mut out = vec![KIND_CHUNKS];
        out.extend_from_slice(&(batch.len() as u32).to_be_bytes());
        for (id, data) in batch.drain(..) {
            out.extend_from_slice(id);
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(data);
        }
        bodies.push(out);
    };
    for c in chunks {
        if size + c.1.len() > MAX_OFFER_BYTES && !batch.is_empty() {
            flush(&mut batch, &mut bodies);
            size = 0;
        }
        size += c.1.len();
        batch.push(c);
    }
    if !batch.is_empty() {
        flush(&mut batch, &mut bodies);
    }
    bodies
}

pub(crate) fn reply_body(msg: &[u8]) -> Vec<u8> {
    let mut out = vec![KIND_REPLY];
    out.extend_from_slice(msg);
    out
}

/// Most IDs one `Offer` asks for, so a long want list is split too.
const MAX_WANT_IDS: usize = MAX_OFFER_BYTES / ChangeId::LEN;

/// One or more `Offer` bodies carrying `changes` and asking for `want`, split to
/// stay under the size limit. Always returns at least one body. Changes too large
/// for a frame are skipped.
pub(crate) fn offer_bodies(want: &[ChangeId], changes: &[Change]) -> Vec<Vec<u8>> {
    let mut bodies = Vec::new();
    let mut want_chunks = want.chunks(MAX_WANT_IDS);
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut size = 0;
    for c in changes {
        let enc = kith_store::codec::encode_change(c);
        if enc.len() > MAX_OFFER_BYTES {
            continue;
        }
        if size + enc.len() > MAX_OFFER_BYTES {
            bodies.push(offer_body(want_chunks.next().unwrap_or(&[]), &batch));
            batch.clear();
            size = 0;
        }
        size += enc.len();
        batch.push(enc);
    }
    if !batch.is_empty() || bodies.is_empty() {
        bodies.push(offer_body(want_chunks.next().unwrap_or(&[]), &batch));
    }
    bodies.extend(want_chunks.map(|chunk| offer_body(chunk, &[])));
    bodies
}

fn offer_body(want: &[ChangeId], changes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![KIND_OFFER];
    put_ids(&mut out, want);
    out.extend_from_slice(&(changes.len() as u32).to_be_bytes());
    for c in changes {
        out.extend_from_slice(&(c.len() as u32).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

fn put_ids(out: &mut Vec<u8>, ids: &[ChangeId]) {
    out.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        out.extend_from_slice(id.as_bytes());
    }
}

pub(crate) fn parse(body: &[u8]) -> Result<Message, String> {
    let (&kind, rest) = body.split_first().ok_or("empty body")?;
    let mut r = Reader(rest);
    let msg = match kind {
        KIND_CHANGE => {
            Message::Change(kith_store::codec::decode_change(rest).map_err(|e| e.to_string())?)
        }
        KIND_QUERY => Message::Query(rest.to_vec()),
        KIND_CHUNK_WANT | KIND_CHUNK_MISSING => {
            let n = r.u32()? as usize;
            if n > r.0.len() / 32 {
                return Err("chunk count exceeds data".into());
            }
            let ids = (0..n)
                .map(|_| Ok(r.take(32)?.try_into().expect("32 bytes")))
                .collect::<Result<Vec<[u8; 32]>, String>>()?;
            if !r.0.is_empty() {
                return Err("trailing bytes".into());
            }
            if kind == KIND_CHUNK_WANT {
                Message::ChunkWant(ids)
            } else {
                Message::ChunkMissing(ids)
            }
        }
        KIND_CHUNKS => {
            let n = r.u32()? as usize;
            if n > r.0.len() / 36 {
                return Err("chunk count exceeds data".into());
            }
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                let id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
                let len = r.u32()? as usize;
                out.push((id, r.take(len)?.to_vec()));
            }
            if !r.0.is_empty() {
                return Err("trailing bytes".into());
            }
            Message::Chunks(out)
        }
        KIND_REPLY => Message::Reply(rest.to_vec()),
        KIND_OFFER => {
            let want = r.ids()?;
            let n = r.u32()? as usize;
            if n > r.0.len() / 4 {
                return Err("change count exceeds data".into());
            }
            let mut changes = Vec::with_capacity(n);
            for _ in 0..n {
                let len = r.u32()? as usize;
                changes.push(r.take(len)?.to_vec());
            }
            Message::Offer { want, changes }
        }
        other => return Err(format!("unknown message kind {other}")),
    };
    if kind == KIND_OFFER && !r.0.is_empty() {
        return Err("trailing bytes".into());
    }
    Ok(msg)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn group(&mut self) -> Result<String, String> {
        let n = self.take(1)?[0] as usize;
        let g = String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "group is not text")?;
        if g.is_empty() {
            return Err("empty group".into());
        }
        Ok(g)
    }

    fn ids(&mut self) -> Result<Vec<ChangeId>, String> {
        let n = self.u32()? as usize;
        // 32 bytes per ID: a huge count fails here instead of allocating.
        if n > self.0.len() / ChangeId::LEN {
            return Err("id count exceeds data".into());
        }
        (0..n)
            .map(|_| {
                Ok(ChangeId(
                    self.take(ChangeId::LEN)?.try_into().expect("32 bytes"),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_roundtrip_and_rejects_garbage() {
        let ids = vec![ChangeId([1; 32]), ChangeId([2; 32])];
        let body = offer_bodies(&ids, &[]).remove(0);
        let Message::Offer { want, changes } = parse(&body).unwrap() else {
            panic!("offer expected")
        };
        assert_eq!(want, ids);
        assert!(changes.is_empty());
        for len in 0..body.len() {
            assert!(parse(&body[..len]).is_err(), "len {len}");
        }
        assert!(parse(&[]).is_err());
        assert!(parse(&[99, 0, 0, 0, 0]).is_err());
        assert!(parse(&[2, 0, 0, 0, 0]).is_err(), "the old Have is gone");
        // Claims a billion IDs but carries none.
        assert!(parse(&[KIND_OFFER, 0x3b, 0x9a, 0xca, 0x00]).is_err());
        assert!(matches!(parse(&query_body(b"q")).unwrap(), Message::Query(q) if q == b"q"));
        assert!(matches!(parse(&reply_body(b"r")).unwrap(), Message::Reply(r) if r == b"r"));
    }

    #[test]
    fn chunk_messages_roundtrip() {
        let ids = vec![[1u8; 32], [2u8; 32]];
        assert!(
            matches!(parse(&chunk_want_bodies(&ids)[0]).unwrap(), Message::ChunkWant(v) if v == ids)
        );
        assert!(
            matches!(parse(&chunk_missing_body(&ids)).unwrap(), Message::ChunkMissing(v) if v == ids)
        );
        let chunks = vec![
            ([3u8; 32], vec![9; 300 * 1024]),
            ([4u8; 32], vec![8; 300 * 1024]),
        ];
        let bodies = chunks_bodies(&chunks);
        assert_eq!(bodies.len(), 2, "split under the size limit");
        let back: Vec<_> = bodies
            .iter()
            .flat_map(|b| match parse(b).unwrap() {
                Message::Chunks(c) => c,
                _ => panic!(),
            })
            .collect();
        assert_eq!(back, chunks);
        assert!(parse(&[KIND_CHUNKS, 0, 0, 0, 9]).is_err());
    }

    #[test]
    fn long_want_lists_are_split() {
        let want: Vec<ChangeId> = (0..40_000u32)
            .map(|i| {
                let mut b = [0; 32];
                b[..4].copy_from_slice(&i.to_be_bytes());
                ChangeId(b)
            })
            .collect();
        let bodies = offer_bodies(&want, &[]);
        assert!(bodies.len() >= 3);
        let back: Vec<ChangeId> = bodies
            .iter()
            .flat_map(|b| match parse(b).unwrap() {
                Message::Offer { want, .. } => want,
                _ => panic!(),
            })
            .collect();
        assert_eq!(back, want);
        assert!(bodies.iter().all(|b| b.len() <= MAX_OFFER_BYTES + 16));
    }

    #[test]
    fn outer_roundtrip_and_rejects_garbage() {
        for msg in [
            Outer::App(vec![1, 2]),
            Outer::Commit(vec![3]),
            Outer::Welcome {
                welcome: vec![4],
                chain: "ab".into(),
            },
            Outer::Welcome {
                welcome: vec![4, 5],
                chain: String::new(),
            },
            Outer::Claim {
                token: [1; 16],
                proof: [2; 32],
                key_package: vec![3],
            },
            Outer::ClaimNonce {
                token: [1; 16],
                nonce: [2; 32],
                signature: [3; 64],
                chain: "ef".into(),
            },
            Outer::Cert("cd".into()),
            Outer::KeyPackage {
                group: "g".into(),
                key_package: vec![5],
            },
            Outer::CommitRequest {
                group: "g/s".into(),
                epoch: 7,
            },
            Outer::Commits {
                group: "g".into(),
                commits: vec![
                    (DeviceId([7; 32]), vec![1]),
                    (DeviceId([8; 32]), vec![2, 3]),
                ],
            },
            Outer::Commits {
                group: "g".into(),
                commits: vec![],
            },
            Outer::ReaddNeeded { group: "g".into() },
        ] {
            assert_eq!(parse_outer(&outer_body(&msg)).unwrap(), msg);
        }
        let body = outer_body(&Outer::Commits {
            group: "g".into(),
            commits: vec![(DeviceId([7; 32]), vec![1, 2])],
        });
        for len in 1..body.len() {
            assert!(parse_outer(&body[..len]).is_err(), "len {len}");
        }
        assert!(parse_outer(&[]).is_err());
        assert!(parse_outer(&[OUTER_APP]).is_err());
        assert!(parse_outer(&[OUTER_READD_NEEDED, 0]).is_err());
        assert!(parse_outer(&[0x99, 1]).is_err());
    }

    /// req: REQ-ENC-001
    #[test]
    fn plaintext_data_bodies_are_refused() {
        // Inner messages sent without MLS are refused by the outer parser.
        assert!(parse_outer(&query_body(b"q")).is_err());
        assert!(parse_outer(&reply_body(b"r")).is_err());
        assert!(parse_outer(&offer_bodies(&[], &[]).remove(0)).is_err());
    }

    #[test]
    fn many_commits_are_split_in_order() {
        let commits: Vec<kith_crypto::group::LoggedCommit> = (0..5u8)
            .map(|i| kith_crypto::group::LoggedCommit {
                committer: DeviceId([i; 32]),
                commit: vec![i; 200 * 1024],
            })
            .collect();
        let bodies = commits_bodies("g", commits.clone());
        assert!(bodies.len() >= 2);
        let back: Vec<(DeviceId, Vec<u8>)> = bodies
            .iter()
            .flat_map(|b| match parse_outer(b).unwrap() {
                Outer::Commits { commits, .. } => commits,
                _ => panic!("commits expected"),
            })
            .collect();
        let want: Vec<(DeviceId, Vec<u8>)> = commits
            .into_iter()
            .map(|c| (c.committer, c.commit))
            .collect();
        assert_eq!(back, want);
    }

    #[test]
    fn empty_offer_is_still_one_body() {
        assert_eq!(offer_bodies(&[], &[]).len(), 1);
    }
}
