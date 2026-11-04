//! Compact binary encoding of a [`Change`] for backends that store opaque
//! blobs (IndexedDB, files, key-value stores).
//!
//! Layout (all integers big-endian): version byte `1`, change id (32),
//! object id (16), author (32), timestamp (u64), signature (64), object type
//! (u32 length + UTF-8), parent count (u32) + 32 bytes each, payload (u32
//! length + bytes). Decoding does not verify the signature; callers that
//! load untrusted data should call [`Change::verify`].

use kith_core::{Change, ChangeId, DeviceId, ObjectId, ObjectType, UnsignedChange};

use crate::StoreError;

const VERSION: u8 = 1;

/// Encode a change into bytes.
pub fn encode_change(c: &Change) -> Vec<u8> {
    let b = &c.body;
    let mut out = Vec::with_capacity(192 + b.payload.len() + 32 * b.parents.len());
    out.push(VERSION);
    out.extend_from_slice(c.change_id.as_bytes());
    out.extend_from_slice(b.object_id.as_bytes());
    out.extend_from_slice(c.author.as_bytes());
    out.extend_from_slice(&b.timestamp_ms.to_be_bytes());
    out.extend_from_slice(&c.signature);
    put_bytes(&mut out, b.object_type.as_str().as_bytes());
    out.extend_from_slice(&(b.parents.len() as u32).to_be_bytes());
    for p in &b.parents {
        out.extend_from_slice(p.as_bytes());
    }
    put_bytes(&mut out, &b.payload);
    out
}

/// Decode bytes produced by [`encode_change`].
pub fn decode_change(bytes: &[u8]) -> Result<Change, StoreError> {
    let mut r = Reader(bytes);
    if r.take(1)?[0] != VERSION {
        return Err(bad("unsupported encoding version"));
    }
    let change_id = ChangeId(r.array()?);
    let object_id = ObjectId(r.array()?);
    let author = DeviceId(r.array()?);
    let timestamp_ms = u64::from_be_bytes(r.array()?);
    let signature = r.array()?;
    let ty = String::from_utf8(r.bytes()?.to_vec()).map_err(|_| bad("object type is not UTF-8"))?;
    let n = u32::from_be_bytes(r.array()?) as usize;
    // Each parent needs 32 bytes, so a huge count fails fast instead of allocating.
    if n > r.0.len() / 32 {
        return Err(bad("parent count exceeds data"));
    }
    let mut parents = Vec::with_capacity(n);
    for _ in 0..n {
        parents.push(ChangeId(r.array()?));
    }
    let payload = r.bytes()?.to_vec();
    if !r.0.is_empty() {
        return Err(bad("trailing bytes"));
    }
    Ok(Change {
        change_id,
        body: UnsignedChange {
            object_id,
            object_type: ObjectType::new(ty),
            parents,
            timestamp_ms,
            payload,
        },
        author,
        signature,
    })
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn bad(what: &str) -> StoreError {
    StoreError::Backend(format!("corrupt change encoding: {what}"))
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if self.0.len() < n {
            return Err(bad("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    fn bytes(&mut self) -> Result<&'a [u8], StoreError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_crypto::DeviceKey;

    fn sample(parents: Vec<ChangeId>, payload: &[u8]) -> Change {
        Change::sign(
            UnsignedChange {
                object_id: ObjectId::random(),
                object_type: ObjectType::new("acme.note"),
                parents,
                timestamp_ms: 1_700_000_000_123,
                payload: payload.to_vec(),
            },
            &DeviceKey::generate(),
        )
    }

    /// req: REQ-STORE-002
    #[test]
    fn roundtrip_keeps_signature_valid() {
        for c in [
            sample(vec![], b""),
            sample(vec![ChangeId([7; 32]), ChangeId([9; 32])], b"payload"),
        ] {
            let back = decode_change(&encode_change(&c)).unwrap();
            assert_eq!(back, c);
            back.verify().unwrap();
        }
    }

    /// req: REQ-STORE-002
    #[test]
    fn rejects_truncated_and_garbage_input() {
        let bytes = encode_change(&sample(vec![ChangeId([1; 32])], b"x"));
        for len in 0..bytes.len() {
            assert!(decode_change(&bytes[..len]).is_err(), "len {len}");
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_change(&extra).is_err());
        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert!(decode_change(&wrong_version).is_err());
    }
}
