//! Catch-up and reconciliation, written sans-IO: functions take state and
//! messages and return messages to send, so the same logic runs over the
//! relay, a direct peer connection, or in a test harness.
//!
//! Phase 3 replaces [`diff`] with Automerge sync / Negentropy
//! (REQ-SYNC-002). The interface stays the same.

use std::collections::HashSet;

use kith_core::ChangeId;

/// What each side must send the other.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Diff {
    /// Changes we have and the peer lacks.
    pub to_send: Vec<ChangeId>,
    /// Changes the peer has and we lack.
    pub to_request: Vec<ChangeId>,
}

/// Naive full-set comparison. Correct but O(n) on the wire; placeholder for
/// range-based set reconciliation.
pub fn diff(local: &[ChangeId], remote: &[ChangeId]) -> Diff {
    let l: HashSet<_> = local.iter().collect();
    let r: HashSet<_> = remote.iter().collect();
    let mut d = Diff {
        to_send: local.iter().filter(|id| !r.contains(id)).copied().collect(),
        to_request: remote
            .iter()
            .filter(|id| !l.contains(id))
            .copied()
            .collect(),
    };
    d.to_send.sort();
    d.to_request.sort();
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> ChangeId {
        ChangeId([b; 32])
    }

    /// req: REQ-SYNC-002
    #[test]
    fn only_missing_changes_are_exchanged() {
        let d = diff(&[id(1), id(2)], &[id(2), id(3)]);
        assert_eq!(d.to_send, vec![id(1)]);
        assert_eq!(d.to_request, vec![id(3)]);
    }

    /// req: REQ-SYNC-003
    #[test]
    fn joining_from_empty_requests_everything() {
        let d = diff(&[], &[id(1), id(2)]);
        assert_eq!(d.to_request, vec![id(1), id(2)]);
        assert!(d.to_send.is_empty());
    }
}
