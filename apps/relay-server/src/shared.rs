//! Shared relay state: orgs, revocations, the allowlist.

use super::*;

pub(crate) struct Conn {
    pub(crate) id: u64,
    pub(crate) tx: Tx,
}

/// Relay state. Opaque outside this crate; create it with [`new_state`].
pub struct Relay {
    pub(crate) table: RoutingTable,
    pub(crate) conns: HashMap<String, Conn>,
    pub(crate) next_conn: AtomicU64,
    pub(crate) auth_timeout: Duration,
    pub(crate) limits: Limits,
    pub(crate) open: Arc<AtomicUsize>,
    pub(crate) org_buckets: HashMap<String, Bucket>,
    /// Per org, the budget its pending devices share (invite claims).
    pub(crate) pending_buckets: HashMap<String, Bucket>,
    /// Open connections per client address (see [`Limits::max_connections_per_ip`]).
    /// Its own lock, so counting needs no relay lock.
    pub(crate) per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Revoked devices remembered, all orgs together.
    pub(crate) revoked_total: usize,
    /// Revoked devices per org (REQ-INV-004), with who revoked them. RAM (and
    /// optionally stored, ADR 0014); admins repeat them on announce.
    pub(crate) revoked: HashMap<String, HashMap<String, Revoked>>,
    /// Certificate chains of announced devices: device -> org -> chain, so a
    /// revocation also removes devices certified through the revoked one.
    pub(crate) proofs: HashMap<String, HashMap<String, CertChain>>,
    /// Orgs this relay serves (REQ-RELAY-008); `None` serves every org.
    pub(crate) allowed_orgs: Option<HashSet<String>>,
    /// Newly accepted revocation notices go here when persistence is on ([`state`]).
    pub(crate) persist: Option<mpsc::UnboundedSender<state::RevocationRecord>>,
}

/// How a device was revoked (ADR 0018).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Revoked {
    /// Signed by the org root key. Only such a notice removes an admin.
    pub(crate) by_root: bool,
    /// The notice's time (issuer's clock).
    pub(crate) issued_ms: u64,
}

/// Does a revocation in `set` reach `chain`? A certificate's device counts as
/// revoked if a notice names it, but an admin only through a root-signed one.
pub(crate) fn chain_revoked(chain: &CertChain, set: &HashMap<String, Revoked>) -> bool {
    chain.0.iter().any(|c| {
        set.get(&c.device.to_hex())
            .is_some_and(|e| e.by_root || !c.admin)
    })
}

/// The canonical form of an org ID (lower-case hex of the root key).
pub(crate) fn canonical_org(org: &str) -> Option<String> {
    DeviceId::from_hex(org).ok().map(|d| d.to_hex())
}

/// Revoked devices remembered per org at most (memory bound).
pub(crate) const MAX_REVOKED_PER_ORG: usize = 10_000;
/// Revoked devices remembered at most, all orgs together (memory bound). Notices
/// beyond it are refused and logged; serve only approved orgs to stay clear of it.
pub(crate) const MAX_REVOKED_TOTAL: usize = 200_000;
/// Revocation notices read from one announce at most (all its orgs together).
pub(crate) const MAX_NOTICES_PER_ANNOUNCE: usize = 256;
/// Orgs in one announce at most; a larger announce is refused as a whole.
pub(crate) const MAX_ORGS_PER_ANNOUNCE: usize = 64;
/// Orgs one device may be announced in at the same time.
pub(crate) const MAX_ORGS_PER_DEVICE: usize = 64;

/// Shared relay state (routing table and live connections).
pub type Shared = Arc<Mutex<Relay>>;

/// Where a connection is in the handshake.
pub(crate) enum Session {
    /// Nothing received yet.
    New,
    /// Challenge sent; waiting for the signature.
    Challenged { device: DeviceId, nonce: String },
    /// Device proved key ownership.
    Authed(String),
}

/// Fresh relay state with default [`Limits`]. `auth_timeout` is how long a new
/// connection has to authenticate.
pub fn new_state(auth_timeout: Duration) -> Shared {
    new_state_with(auth_timeout, Limits::default())
}

/// Fresh relay state with the given abuse limits.
pub fn new_state_with(auth_timeout: Duration, limits: Limits) -> Shared {
    Arc::new(Mutex::new(Relay {
        table: RoutingTable::default(),
        conns: HashMap::new(),
        next_conn: AtomicU64::new(0),
        auth_timeout,
        limits,
        open: Arc::new(AtomicUsize::new(0)),
        org_buckets: HashMap::new(),
        pending_buckets: HashMap::new(),
        per_ip: Arc::new(Mutex::new(HashMap::new())),
        revoked_total: 0,
        revoked: HashMap::new(),
        proofs: HashMap::new(),
        allowed_orgs: None,
        persist: None,
    }))
}

/// Parse an org list as given in `KITH_RELAY_ALLOWED_ORGS`: org IDs separated by commas
/// or whitespace, compared case-insensitively. No entries means no restriction (`None`).
pub fn parse_allowed_orgs(list: &str) -> Option<HashSet<String>> {
    let orgs: HashSet<String> = list
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    (!orgs.is_empty()).then_some(orgs)
}

/// Restrict the relay to `orgs` (`None` serves every org). Devices that are online in an
/// org no longer on the list are removed from it and told (`org-not-allowed`); their
/// connections stay open for their other orgs.
pub fn set_allowed_orgs(state: &Shared, orgs: Option<HashSet<String>>) {
    let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
    r.allowed_orgs = orgs;
    let Some(allowed) = r.allowed_orgs.clone() else {
        return;
    };
    for org in r.table.orgs() {
        if allowed.contains(&org.to_ascii_lowercase()) {
            continue;
        }
        for dev in r.table.devices_in(&org) {
            r.table.kick(&dev, &org);
            if let Some(m) = r.proofs.get_mut(&dev) {
                m.remove(&org);
            }
            if let Some(conn) = r.conns.get(&dev) {
                send(
                    &conn.tx,
                    error(
                        "org-not-allowed",
                        format!("{org}: this relay no longer serves this organization"),
                    ),
                );
            }
        }
        forget_if_empty(&mut r, &org);
    }
}

/// Counts an open connection for as long as it lives.
pub(crate) struct OpenGuard(pub(crate) Arc<AtomicUsize>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
