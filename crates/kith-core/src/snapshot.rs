//! Snapshot payloads (history compaction, REQ-DATA-005, ADR 0026).
//!
//! A snapshot is an ordinary signed change on an object whose payload starts with
//! [`MAGIC`]. It names the changes it **covers** and carries, for documents, their
//! payloads (the *bundle*). A device that accepts a snapshot (author is an admin)
//! deletes the covered changes and remembers only their IDs, so sync never asks for
//! them again. Objects without a merger (raw objects) carry no bundle: their covered
//! changes are simply gone.

use crate::ChangeId;

/// First bytes of a snapshot payload. Apps cannot write payloads that start with it.
pub const MAGIC: &[u8] = b"kith/snapshot/v1\0";

/// Largest encoded snapshot. A change travels in one relay frame (1 MiB) inside an
/// offer of at most 512 KiB, so a snapshot has to stay below that.
pub const MAX_ENCODED: usize = 400 * 1024;

/// Most changes one snapshot covers.
pub const MAX_COVERS: usize = 10_000;

/// A parsed snapshot payload.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// IDs of the changes folded into this snapshot.
    pub covers: Vec<ChangeId>,
    /// Payloads of the covered changes that a merger needs, in causal order (empty for
    /// raw objects).
    pub bundle: Vec<Vec<u8>>,
}

/// True if `payload` is shaped like a snapshot (valid or not).
pub fn is_snapshot(payload: &[u8]) -> bool {
    payload.starts_with(MAGIC)
}

impl Snapshot {
    /// Payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&(self.covers.len() as u32).to_be_bytes());
        for id in &self.covers {
            out.extend_from_slice(id.as_bytes());
        }
        out.extend_from_slice(&(self.bundle.len() as u32).to_be_bytes());
        for b in &self.bundle {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        out
    }

    /// Size [`Self::encode`] would produce, without building it.
    pub fn encoded_len(&self) -> usize {
        MAGIC.len()
            + 8
            + self.covers.len() * 32
            + self.bundle.iter().map(|b| 4 + b.len()).sum::<usize>()
    }

    /// Parse a snapshot payload; `None` if it is not one or is malformed.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut r = payload.strip_prefix(MAGIC)?;
        let mut take = |n: usize| -> Option<&[u8]> {
            let (a, b) = r.split_at_checked(n)?;
            r = b;
            Some(a)
        };
        let n = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
        if n > MAX_COVERS || n.checked_mul(32)? > payload.len() {
            return None;
        }
        let covers = (0..n)
            .map(|_| {
                take(32)
                    .and_then(|c| <[u8; 32]>::try_from(c).ok())
                    .map(ChangeId)
            })
            .collect::<Option<Vec<_>>>()?;
        let m = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
        if m > payload.len() / 4 {
            return None;
        }
        let mut bundle = Vec::with_capacity(m);
        for _ in 0..m {
            let len = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
            bundle.push(take(len)?.to_vec());
        }
        if !r.is_empty() {
            return None;
        }
        Some(Self { covers, bundle })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejects_garbage() {
        let s = Snapshot {
            covers: vec![ChangeId([1; 32]), ChangeId([2; 32])],
            bundle: vec![vec![1, 2, 3], vec![]],
        };
        let b = s.encode();
        assert_eq!(b.len(), s.encoded_len());
        assert!(is_snapshot(&b));
        assert_eq!(Snapshot::decode(&b), Some(s));
        for len in 0..b.len() {
            assert!(Snapshot::decode(&b[..len]).is_none(), "len {len}");
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(Snapshot::decode(&extra).is_none());
        assert!(Snapshot::decode(b"not a snapshot").is_none());
        // A count that claims more IDs than there are bytes.
        let mut huge = MAGIC.to_vec();
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(Snapshot::decode(&huge).is_none());
    }
}
