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
    /// A new membership certificate chain for the receiver (hex), e.g. admin rights.
    Cert(String),
    /// KeyPackage of a device that wants to be added (or re-added), direct to a member.
    KeyPackage(Vec<u8>),
    /// "I am at this epoch, send me the commits since."
    CommitRequest(u64),
    /// Commits in epoch order with their committers, answering a `CommitRequest`
    /// (or showing a peer on a losing fork branch the winning commit).
    Commits(Vec<(DeviceId, Vec<u8>)>),
    /// "My commit log does not reach back to your epoch; send a KeyPackage to be re-added."
    ReaddNeeded,
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
        Outer::Cert(chain) => (OUTER_CERT, chain.as_bytes()),
        Outer::KeyPackage(b) => (OUTER_KEY_PACKAGE, b),
        Outer::CommitRequest(e) => {
            let mut out = vec![OUTER_COMMIT_REQUEST];
            out.extend_from_slice(&e.to_be_bytes());
            return out;
        }
        Outer::Commits(cs) => {
            let mut out = vec![OUTER_COMMITS];
            out.extend_from_slice(&(cs.len() as u32).to_be_bytes());
            for (committer, c) in cs {
                out.extend_from_slice(&committer.0);
                out.extend_from_slice(&(c.len() as u32).to_be_bytes());
                out.extend_from_slice(c);
            }
            return out;
        }
        Outer::ReaddNeeded => return vec![OUTER_READD_NEEDED],
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

/// `Commits` bodies for `commits`, split to stay under the frame limit, in order.
pub(crate) fn commits_bodies(commits: Vec<kith_crypto::group::LoggedCommit>) -> Vec<Vec<u8>> {
    let mut bodies = vec![];
    let mut batch = vec![];
    let mut size = 0;
    for c in commits {
        if size + c.commit.len() > MAX_OFFER_BYTES && !batch.is_empty() {
            bodies.push(outer_body(&Outer::Commits(std::mem::take(&mut batch))));
            size = 0;
        }
        size += c.commit.len();
        batch.push((c.committer, c.commit));
    }
    if !batch.is_empty() {
        bodies.push(outer_body(&Outer::Commits(batch)));
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
        OUTER_CERT => Outer::Cert(
            String::from_utf8(rest.to_vec()).map_err(|_| "certificate chain is not text")?,
        ),
        OUTER_KEY_PACKAGE => Outer::KeyPackage(rest.to_vec()),
        OUTER_COMMIT_REQUEST => {
            Outer::CommitRequest(u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes")))
        }
        OUTER_COMMITS => {
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
            Outer::Commits(cs)
        }
        OUTER_READD_NEEDED => Outer::ReaddNeeded,
        // 1..=3 were plaintext data bodies before MLS (hard break, ADR 0004).
        1..=3 => return Err("unencrypted body refused".into()),
        other => return Err(format!("unknown body kind {other}")),
    };
    let fixed = matches!(
        kind,
        OUTER_COMMIT_REQUEST | OUTER_COMMITS | OUTER_READD_NEEDED | OUTER_WELCOME | OUTER_CLAIM
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
            Outer::Cert("cd".into()),
            Outer::KeyPackage(vec![5]),
            Outer::CommitRequest(7),
            Outer::Commits(vec![
                (DeviceId([7; 32]), vec![1]),
                (DeviceId([8; 32]), vec![2, 3]),
            ]),
            Outer::Commits(vec![]),
            Outer::ReaddNeeded,
        ] {
            assert_eq!(parse_outer(&outer_body(&msg)).unwrap(), msg);
        }
        let body = outer_body(&Outer::Commits(vec![(DeviceId([7; 32]), vec![1, 2])]));
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
        let bodies = commits_bodies(commits.clone());
        assert!(bodies.len() >= 2);
        let back: Vec<(DeviceId, Vec<u8>)> = bodies
            .iter()
            .flat_map(|b| match parse_outer(b).unwrap() {
                Outer::Commits(cs) => cs,
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
