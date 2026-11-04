//! Catch-up sync messages (REQ-SYNC-001..003), sans-IO.
//!
//! Everything travels in the opaque `body` of relay frames as `[kind][payload]`:
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
//! based reconciliation (Negentropy) replaces it. TODO(phase 4): bodies are
//! plaintext on the relay until MLS lands.

use kith_core::{Change, ChangeId};
use kith_protocol::MAX_BODY_BYTES;

const KIND_CHANGE: u8 = 1;
const KIND_HAVE: u8 = 2;
const KIND_OFFER: u8 = 3;

/// Stay well below the frame limit: the body is JSON-encoded by the relay protocol
/// only after this check, and one oversized change must not block the others.
const MAX_OFFER_BYTES: usize = 512 * 1024;

/// A parsed relay body.
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
    fn empty_offer_is_still_one_body() {
        assert_eq!(offer_bodies(&[], &[]).len(), 1);
    }
}
