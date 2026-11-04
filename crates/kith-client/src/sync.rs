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
//! - `Have`: all change IDs the sender has. Sent as a `SyncRequest`, which the
//!   relay hands to one online peer.
//! - `Offer`: the changes the receiver of a `Have` lacks, plus the IDs the sender
//!   of the offer wants back. Sent as a `Direct` to the requester, which answers
//!   with a second `Offer` carrying what the partner wanted.
//!
//! The set comparison is the naive full-ID exchange of `kith_sync::diff`; the
//! `Have` message therefore caps at about 32,000 changes per device until range
//! based reconciliation (Negentropy) replaces it.

use kith_core::{Change, ChangeId};
use kith_protocol::MAX_BODY_BYTES;

const KIND_CHANGE: u8 = 1;
const KIND_HAVE: u8 = 2;
const KIND_OFFER: u8 = 3;

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

/// A parsed relay body (outer layer).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outer {
    /// MLS application message; plaintext is an inner [`Message`].
    App(Vec<u8>),
    /// MLS commit, broadcast to the group.
    Commit(Vec<u8>),
    /// MLS Welcome, direct to a new member.
    Welcome(Vec<u8>),
    /// KeyPackage of a device that wants to be added (or re-added), direct to a member.
    KeyPackage(Vec<u8>),
    /// "I am at this epoch, send me the commits since."
    CommitRequest(u64),
    /// Commits in epoch order, answering a `CommitRequest`.
    Commits(Vec<Vec<u8>>),
    /// "My commit log does not reach back to your epoch; send a KeyPackage to be re-added."
    ReaddNeeded,
}

pub(crate) fn outer_body(msg: &Outer) -> Vec<u8> {
    let (kind, payload): (u8, &[u8]) = match msg {
        Outer::App(b) => (OUTER_APP, b),
        Outer::Commit(b) => (OUTER_COMMIT, b),
        Outer::Welcome(b) => (OUTER_WELCOME, b),
        Outer::KeyPackage(b) => (OUTER_KEY_PACKAGE, b),
        Outer::CommitRequest(e) => {
            let mut out = vec![OUTER_COMMIT_REQUEST];
            out.extend_from_slice(&e.to_be_bytes());
            return out;
        }
        Outer::Commits(cs) => {
            let mut out = vec![OUTER_COMMITS];
            out.extend_from_slice(&(cs.len() as u32).to_be_bytes());
            for c in cs {
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
pub(crate) fn commits_bodies(commits: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut bodies = vec![];
    let mut batch = vec![];
    let mut size = 0;
    for c in commits {
        if size + c.len() > MAX_OFFER_BYTES && !batch.is_empty() {
            bodies.push(outer_body(&Outer::Commits(std::mem::take(&mut batch))));
            size = 0;
        }
        size += c.len();
        batch.push(c);
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
        OUTER_WELCOME => Outer::Welcome(rest.to_vec()),
        OUTER_KEY_PACKAGE => Outer::KeyPackage(rest.to_vec()),
        OUTER_COMMIT_REQUEST => {
            Outer::CommitRequest(u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes")))
        }
        OUTER_COMMITS => {
            let n = r.u32()? as usize;
            if n > r.0.len() / 4 {
                return Err("commit count exceeds data".into());
            }
            let mut cs = Vec::with_capacity(n);
            for _ in 0..n {
                let len = r.u32()? as usize;
                cs.push(r.take(len)?.to_vec());
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
        OUTER_COMMIT_REQUEST | OUTER_COMMITS | OUTER_READD_NEEDED
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
    Have(Vec<ChangeId>),
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

/// Largest number of IDs a `Have` can carry.
pub(crate) const MAX_HAVE_IDS: usize = (MAX_BODY_BYTES - 5) / ChangeId::LEN;

pub(crate) fn have_body(ids: &[ChangeId]) -> Vec<u8> {
    let mut out = vec![KIND_HAVE];
    put_ids(&mut out, ids);
    out
}

/// One or more `Offer` bodies carrying `changes`, split to stay under the size
/// limit. `want` goes into the first one. Always returns at least one body.
/// Changes too large for a frame are skipped.
pub(crate) fn offer_bodies(want: &[ChangeId], changes: &[Change]) -> Vec<Vec<u8>> {
    let mut bodies = Vec::new();
    let mut want = Some(want);
    let mut batch: Vec<Vec<u8>> = Vec::new();
    let mut size = 0;
    let mut flush = |batch: &mut Vec<Vec<u8>>, want: &mut Option<&[ChangeId]>| {
        let mut out = vec![KIND_OFFER];
        put_ids(&mut out, want.take().unwrap_or(&[]));
        out.extend_from_slice(&(batch.len() as u32).to_be_bytes());
        for c in batch.drain(..) {
            out.extend_from_slice(&(c.len() as u32).to_be_bytes());
            out.extend_from_slice(&c);
        }
        bodies.push(out);
    };
    for c in changes {
        let enc = kith_store::codec::encode_change(c);
        if enc.len() > MAX_OFFER_BYTES {
            continue;
        }
        if size + enc.len() > MAX_OFFER_BYTES {
            flush(&mut batch, &mut want);
            size = 0;
        }
        size += enc.len();
        batch.push(enc);
    }
    if !batch.is_empty() || want.is_some() {
        flush(&mut batch, &mut want);
    }
    bodies
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
        KIND_HAVE => Message::Have(r.ids()?),
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
    if kind != KIND_CHANGE && !r.0.is_empty() {
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
    fn have_roundtrip_and_rejects_garbage() {
        let ids = vec![ChangeId([1; 32]), ChangeId([2; 32])];
        let Message::Have(back) = parse(&have_body(&ids)).unwrap() else {
            panic!("have expected")
        };
        assert_eq!(back, ids);
        let body = have_body(&ids);
        for len in 0..body.len() {
            assert!(parse(&body[..len]).is_err(), "len {len}");
        }
        assert!(parse(&[]).is_err());
        assert!(parse(&[99, 0, 0, 0, 0]).is_err());
        // Claims a billion IDs but carries none.
        assert!(parse(&[KIND_HAVE, 0x3b, 0x9a, 0xca, 0x00]).is_err());
    }

    #[test]
    fn outer_roundtrip_and_rejects_garbage() {
        for msg in [
            Outer::App(vec![1, 2]),
            Outer::Commit(vec![3]),
            Outer::Welcome(vec![4]),
            Outer::KeyPackage(vec![5]),
            Outer::CommitRequest(7),
            Outer::Commits(vec![vec![1], vec![2, 3]]),
            Outer::Commits(vec![]),
            Outer::ReaddNeeded,
        ] {
            assert_eq!(parse_outer(&outer_body(&msg)).unwrap(), msg);
        }
        let body = outer_body(&Outer::Commits(vec![vec![1], vec![2, 3]]));
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
        let ids = vec![ChangeId([1; 32])];
        assert!(parse_outer(&have_body(&ids)).is_err());
        assert!(parse_outer(&offer_bodies(&[], &[]).remove(0)).is_err());
    }

    #[test]
    fn many_commits_are_split_in_order() {
        let commits: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 200 * 1024]).collect();
        let bodies = commits_bodies(commits.clone());
        assert!(bodies.len() >= 2);
        let back: Vec<Vec<u8>> = bodies
            .iter()
            .flat_map(|b| match parse_outer(b).unwrap() {
                Outer::Commits(cs) => cs,
                _ => panic!("commits expected"),
            })
            .collect();
        assert_eq!(back, commits);
    }

    #[test]
    fn empty_offer_is_still_one_body() {
        assert_eq!(offer_bodies(&[], &[]).len(), 1);
    }
}
