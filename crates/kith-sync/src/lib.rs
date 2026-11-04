//! Catch-up reconciliation, written sans-IO: functions take state and messages
//! and return messages to send, so the same logic runs over the relay, a direct
//! peer connection, or in a test harness.
//!
//! Range-based set reconciliation with [Negentropy](https://github.com/hoytech/negentropy)
//! (REQ-SYNC-002): the sets of change IDs are compared by fingerprints of ID
//! ranges, so the traffic grows with the size of the *difference*, not of the
//! history, and no message exceeds [`FRAME_LIMIT`]. The requester runs a
//! [`Reconciliation`]; the peer answers each message with [`respond`], keeping no
//! state between rounds.

use kith_core::ChangeId;
use negentropy::{Id, Negentropy, NegentropyStorageVector};

/// Upper bound for one reconciliation message (well below the relay's frame limit,
/// leaving room for encryption and framing).
pub const FRAME_LIMIT: u64 = 256 * 1024;

/// What each side must send the other.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Changes we have and the peer lacks.
    pub to_send: Vec<ChangeId>,
    /// Changes the peer has and we lack.
    pub to_request: Vec<ChangeId>,
}

/// A malformed reconciliation message (or an internal limit was hit).
#[derive(Debug, thiserror::Error)]
#[error("reconciliation: {0}")]
pub struct SyncError(String);

fn err(e: impl std::fmt::Debug) -> SyncError {
    SyncError(format!("{e:?}"))
}

fn storage(ids: &[ChangeId]) -> Result<NegentropyStorageVector, SyncError> {
    let mut s = NegentropyStorageVector::with_capacity(ids.len());
    // All items get timestamp 0: ranges then split by ID only. Change IDs are
    // hashes, so they are spread evenly, and no change has to be loaded for its time.
    for id in ids {
        s.insert(0, Id::from_byte_array(id.0)).map_err(err)?;
    }
    s.seal().map_err(err)?;
    Ok(s)
}

/// The requesting side of one reconciliation.
pub struct Reconciliation {
    neg: Negentropy<'static, NegentropyStorageVector>,
    diff: Diff,
}

impl std::fmt::Debug for Reconciliation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reconciliation")
            .field("diff", &self.diff)
            .finish_non_exhaustive()
    }
}

/// Result of one [`Reconciliation::step`].
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Send this to the peer and feed its answer to `step` again.
    Continue(Vec<u8>),
    /// Done: what each side lacks.
    Done(Diff),
}

impl Reconciliation {
    /// Start reconciling our `local` IDs with a peer. Returns the first message.
    pub fn start(local: &[ChangeId]) -> Result<(Self, Vec<u8>), SyncError> {
        let mut neg = Negentropy::owned(storage(local)?, FRAME_LIMIT).map_err(err)?;
        let first = neg.initiate().map_err(err)?;
        Ok((
            Self {
                neg,
                diff: Diff::default(),
            },
            first,
        ))
    }

    /// Process the peer's answer.
    pub fn step(&mut self, answer: &[u8]) -> Result<Step, SyncError> {
        let (mut have, mut need) = (Vec::new(), Vec::new());
        let next = self
            .neg
            .reconcile_with_ids(answer, &mut have, &mut need)
            .map_err(err)?;
        self.diff
            .to_send
            .extend(have.iter().map(|id| ChangeId(*id.as_bytes())));
        self.diff
            .to_request
            .extend(need.iter().map(|id| ChangeId(*id.as_bytes())));
        Ok(match next {
            Some(msg) => Step::Continue(msg),
            None => {
                let mut diff = std::mem::take(&mut self.diff);
                diff.to_send.sort();
                diff.to_send.dedup();
                diff.to_request.sort();
                diff.to_request.dedup();
                Step::Done(diff)
            }
        })
    }
}

/// The answering side: reply to one message of a peer's [`Reconciliation`].
pub fn respond(local: &[ChangeId], query: &[u8]) -> Result<Vec<u8>, SyncError> {
    Negentropy::owned(storage(local)?, FRAME_LIMIT)
        .map_err(err)?
        .reconcile(query)
        .map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u32) -> ChangeId {
        // Spread like real hashes.
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.wrapping_mul(2_654_435_761).to_be_bytes());
        b[4..8].copy_from_slice(&n.to_be_bytes());
        ChangeId(b)
    }

    /// Run a whole reconciliation; returns the diff and the largest message size.
    fn run(local: &[ChangeId], remote: &[ChangeId]) -> (Diff, usize, usize) {
        let (mut r, mut msg) = Reconciliation::start(local).unwrap();
        let (mut largest, mut rounds) = (msg.len(), 0);
        loop {
            let answer = respond(remote, &msg).unwrap();
            largest = largest.max(answer.len());
            rounds += 1;
            match r.step(&answer).unwrap() {
                Step::Continue(m) => {
                    largest = largest.max(m.len());
                    msg = m;
                }
                Step::Done(d) => return (d, largest, rounds),
            }
        }
    }

    /// req: REQ-SYNC-002
    #[test]
    fn only_missing_changes_are_exchanged() {
        let (d, _, _) = run(&[id(1), id(2)], &[id(2), id(3)]);
        assert_eq!(d.to_send, vec![id(1)]);
        assert_eq!(d.to_request, vec![id(3)]);
        let (d, _, _) = run(&[id(1)], &[id(1)]);
        assert_eq!(d, Diff::default());
    }

    /// req: REQ-SYNC-003
    #[test]
    fn joining_from_empty_requests_everything() {
        let (d, _, _) = run(&[], &[id(1), id(2)]);
        let mut want = vec![id(1), id(2)];
        want.sort();
        assert_eq!(d.to_request, want);
        assert!(d.to_send.is_empty());
    }

    /// req: REQ-SYNC-002
    #[test]
    fn large_sets_with_small_differences_stay_small_on_the_wire() {
        let common: Vec<ChangeId> = (0..100_000).map(id).collect();
        let mut local = common.clone();
        local.extend((200_000..200_010).map(id));
        let mut remote = common;
        remote.extend((300_000..300_005).map(id));
        let (d, largest, _) = run(&local, &remote);
        assert_eq!(d.to_send.len(), 10);
        assert_eq!(d.to_request.len(), 5);
        // A full ID list would be 3.2 MB; fingerprints keep every message far smaller.
        assert!(largest < 64 * 1024, "largest message {largest} bytes");
    }

    /// req: REQ-SYNC-003
    #[test]
    fn a_big_history_arrives_in_frames_under_the_limit() {
        let remote: Vec<ChangeId> = (0..60_000).map(id).collect();
        let (d, largest, rounds) = run(&[], &remote);
        assert_eq!(d.to_request.len(), 60_000);
        assert!(largest as u64 <= FRAME_LIMIT + 1024, "largest {largest}");
        assert!(rounds > 1, "split over several rounds");
    }

    #[test]
    fn garbage_is_an_error() {
        assert!(respond(&[id(1)], b"\x99garbage").is_err());
        let (mut r, _) = Reconciliation::start(&[id(1)]).unwrap();
        assert!(r.step(b"\x99garbage").is_err());
    }
}
