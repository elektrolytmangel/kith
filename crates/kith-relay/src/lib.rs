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

/// What a device may do in an org, as proven on `announce` (REQ-RELAY-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// No valid membership proof yet (a device claiming an invite): may only send
    /// invite claims and receive direct messages. Not in presence.
    Pending,
    /// A member.
    Member,
    /// A member that may admit others; invite claims are routed to admins.
    Admin,
}

/// Who is online in which organization. RAM only.
#[derive(Default, Debug)]
pub struct RoutingTable {
    /// Members and admins.
    orgs: HashMap<OrgId, HashSet<DeviceIdHex>>,
    admins: HashMap<OrgId, HashSet<DeviceIdHex>>,
    pending: HashMap<OrgId, HashSet<DeviceIdHex>>,
    devices: HashMap<DeviceIdHex, HashSet<OrgId>>,
    /// Devices preferred as sync partners (always-on clients).
    always_on: HashSet<DeviceIdHex>,
}

impl RoutingTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authenticated device as an online member of `org`.
    /// Membership proofs must be checked by the caller before this.
    pub fn join(&mut self, device: &str, org: &str) {
        self.join_as(device, org, Role::Member);
    }

    /// Register an authenticated device in `org` with `role` (replacing an earlier
    /// role, e.g. pending → member after joining).
    pub fn join_as(&mut self, device: &str, org: &str, role: Role) {
        self.leave(device, org);
        let set = match role {
            Role::Pending => &mut self.pending,
            Role::Member | Role::Admin => &mut self.orgs,
        };
        set.entry(org.into()).or_default().insert(device.into());
        if role == Role::Admin {
            self.admins
                .entry(org.into())
                .or_default()
                .insert(device.into());
        }
        self.devices
            .entry(device.into())
            .or_default()
            .insert(org.into());
    }

    /// Take `device` out of `org` only (it was revoked there). Its other orgs stay.
    pub fn kick(&mut self, device: &str, org: &str) {
        self.leave(device, org);
        if let Some(orgs) = self.devices.get_mut(device) {
            orgs.remove(org);
            if orgs.is_empty() {
                self.devices.remove(device);
                self.always_on.remove(device);
            }
        }
    }

    fn leave(&mut self, device: &str, org: &str) {
        for map in [&mut self.orgs, &mut self.admins, &mut self.pending] {
            if let Some(set) = map.get_mut(org) {
                set.remove(device);
                if set.is_empty() {
                    map.remove(org);
                }
            }
        }
    }

    /// The device's role in `org`, if it announced it.
    pub fn role(&self, org: &str, device: &str) -> Option<Role> {
        let has = |m: &HashMap<OrgId, HashSet<DeviceIdHex>>| {
            m.get(org).is_some_and(|s| s.contains(device))
        };
        if has(&self.admins) {
            Some(Role::Admin)
        } else if has(&self.orgs) {
            Some(Role::Member)
        } else if has(&self.pending) {
            Some(Role::Pending)
        } else {
            None
        }
    }

    /// Online admins of `org`, sorted (where invite claims go).
    pub fn admins(&self, org: &str) -> Route {
        let mut v: Vec<_> = self
            .admins
            .get(org)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        v.sort();
        if v.is_empty() {
            Route::Dropped
        } else {
            Route::To(v)
        }
    }

    /// Where an own-device invite claim goes (ADR 0011): the named device, if it is
    /// an online certified member (not a pending one). Dropped otherwise.
    pub fn member(&self, org: &str, to: &str) -> Route {
        match self.role(org, to) {
            Some(Role::Member | Role::Admin) => Route::To(vec![to.into()]),
            _ => Route::Dropped,
        }
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
                self.leave(device, &org);
            }
        }
        self.always_on.remove(device);
    }

    /// Every device announced in `org`, members and pending ones, sorted.
    pub fn devices_in(&self, org: &str) -> Vec<DeviceIdHex> {
        let mut v: Vec<_> = [&self.orgs, &self.pending]
            .into_iter()
            .filter_map(|m| m.get(org))
            .flatten()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Orgs that have at least one online or pending device, sorted.
    pub fn orgs(&self) -> Vec<OrgId> {
        let mut v: Vec<_> = [&self.orgs, &self.pending]
            .into_iter()
            .flat_map(|m| m.iter())
            .filter(|(_, devs)| !devs.is_empty())
            .map(|(org, _)| org.clone())
            .collect();
        v.sort();
        v.dedup();
        v
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

    /// One device, if it is online in `org` (members and pending devices, so a
    /// Welcome reaches a device that is joining).
    pub fn direct(&self, org: &str, to: &str) -> Route {
        if self.role(org, to).is_some() {
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
        t.join_as("p", "org", Role::Pending);
        t.join_as("q", "org", Role::Admin);
        t.disconnect("p");
        t.disconnect("q");
        assert!(t.pending.is_empty() && t.admins.is_empty() && t.orgs.is_empty());
    }

    /// req: REQ-RELAY-004
    #[test]
    fn pending_devices_get_directs_but_no_presence_and_claims_go_to_admins() {
        let mut t = RoutingTable::new();
        t.join_as("admin", "org", Role::Admin);
        t.join("member", "org");
        t.join_as("new", "org", Role::Pending);
        assert_eq!(t.online("org"), vec!["admin".to_string(), "member".into()]);
        assert_eq!(
            t.broadcast("org", "member"),
            Route::To(vec!["admin".into()])
        );
        assert_eq!(t.direct("org", "new"), Route::To(vec!["new".into()]));
        assert_eq!(t.admins("org"), Route::To(vec!["admin".into()]));
        assert_eq!(t.role("org", "new"), Some(Role::Pending));
        // Joining moves the device from pending to member.
        t.join("new", "org");
        assert_eq!(t.role("org", "new"), Some(Role::Member));
        assert_eq!(t.online("org").len(), 3);
        assert_eq!(t.admins("other"), Route::Dropped);
    }

    /// req: REQ-INV-004
    #[test]
    fn kick_removes_a_device_from_one_org_only() {
        let mut t = RoutingTable::new();
        t.join("a", "org");
        t.join("a", "other");
        t.kick("a", "org");
        assert_eq!(t.role("org", "a"), None);
        assert_eq!(t.role("other", "a"), Some(Role::Member));
        t.kick("a", "other");
        assert!(t.devices.is_empty());
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
