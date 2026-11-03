//! Relay routing logic.
//!
//! Pure, in-memory routing state with no I/O and no storage dependencies,
//! so "the relay persists nothing" (REQ-RELAY-001) holds by construction.
//! `apps/relay-server` wraps this in a WebSocket server; you can embed it
//! in your own server instead (see `docs/guides/adapting.md`).

use std::collections::{HashMap, HashSet};

use kith_protocol::{DeviceIdHex, OrgId};

/// Where a message should go.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Deliver to these devices.
    To(Vec<DeviceIdHex>),
    /// Nobody online to receive it; the message is dropped.
    Dropped,
}

/// Who is online in which organization. RAM only.
#[derive(Default, Debug)]
pub struct RoutingTable {
    orgs: HashMap<OrgId, HashSet<DeviceIdHex>>,
    devices: HashMap<DeviceIdHex, HashSet<OrgId>>,
    /// Devices preferred as sync partners (always-on clients).
    always_on: HashSet<DeviceIdHex>,
}

impl RoutingTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authenticated device as online in `org`.
    /// Membership proofs must be checked by the caller before this.
    pub fn join(&mut self, device: &str, org: &str) {
        self.orgs
            .entry(org.into())
            .or_default()
            .insert(device.into());
        self.devices
            .entry(device.into())
            .or_default()
            .insert(org.into());
    }

    /// Mark a device as an always-on client (preferred for catch-up).
    pub fn set_always_on(&mut self, device: &str, on: bool) {
        if on {
            self.always_on.insert(device.into());
        } else {
            self.always_on.remove(device);
        }
    }

    /// Forget a device entirely (connection closed).
    pub fn disconnect(&mut self, device: &str) {
        if let Some(orgs) = self.devices.remove(device) {
            for org in orgs {
                if let Some(set) = self.orgs.get_mut(&org) {
                    set.remove(device);
                    if set.is_empty() {
                        self.orgs.remove(&org);
                    }
                }
            }
        }
        self.always_on.remove(device);
    }

    /// Online devices in an org, sorted.
    pub fn online(&self, org: &str) -> Vec<DeviceIdHex> {
        let mut v: Vec<_> = self.orgs.get(org).into_iter().flatten().cloned().collect();
        v.sort();
        v
    }

    /// All online devices in `org` except the sender.
    pub fn broadcast(&self, org: &str, from: &str) -> Route {
        let to: Vec<_> = self.online(org).into_iter().filter(|d| d != from).collect();
        if to.is_empty() {
            Route::Dropped
        } else {
            Route::To(to)
        }
    }

    /// One device, if it is online in `org`.
    pub fn direct(&self, org: &str, to: &str) -> Route {
        if self.orgs.get(org).is_some_and(|s| s.contains(to)) {
            Route::To(vec![to.into()])
        } else {
            Route::Dropped
        }
    }

    /// Pick one online peer for catch-up, preferring always-on clients.
    pub fn sync_partner(&self, org: &str, from: &str) -> Route {
        let candidates: Vec<_> = self.online(org).into_iter().filter(|d| d != from).collect();
        let pick = candidates
            .iter()
            .find(|d| self.always_on.contains(*d))
            .or_else(|| candidates.first())
            .cloned();
        match pick {
            Some(d) => Route::To(vec![d]),
            None => Route::Dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// req: REQ-RELAY-002
    #[test]
    fn broadcast_reaches_online_members_except_sender() {
        let mut t = RoutingTable::new();
        t.join("a", "org");
        t.join("b", "org");
        t.join("c", "other");
        assert_eq!(t.broadcast("org", "a"), Route::To(vec!["b".into()]));
    }

    /// req: REQ-RELAY-003
    #[test]
    fn messages_to_offline_devices_are_dropped() {
        let mut t = RoutingTable::new();
        t.join("a", "org");
        assert_eq!(t.direct("org", "b"), Route::Dropped);
        assert_eq!(t.broadcast("org", "a"), Route::Dropped);
    }

    /// req: REQ-RELAY-001
    #[test]
    fn disconnect_forgets_everything() {
        let mut t = RoutingTable::new();
        t.join("a", "org");
        t.set_always_on("a", true);
        t.disconnect("a");
        assert!(t.online("org").is_empty());
        assert!(t.orgs.is_empty() && t.devices.is_empty() && t.always_on.is_empty());
    }

    /// req: REQ-SYNC-001
    #[test]
    fn sync_prefers_always_on_client() {
        let mut t = RoutingTable::new();
        for d in ["a", "b", "z"] {
            t.join(d, "org");
        }
        t.set_always_on("z", true);
        assert_eq!(t.sync_partner("org", "a"), Route::To(vec!["z".into()]));
    }
}
