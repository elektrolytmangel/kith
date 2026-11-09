//! High-level client SDK.
//!
//! This is the API apps program against, either directly (Rust desktop
//! apps, Tauri, headless always-on clients) or through the generated
//! bindings in `bindings/` (Swift, Kotlin, JavaScript/WASM).
//!
//! Every relay body is end-to-end encrypted with the organization's MLS group
//! (REQ-ENC-001, ADR 0004). [`Client::create_org`] creates an organization (its
//! root key, ID and group); an admin issues invites ([`Client::create_invite`]),
//! a new device claims one ([`Client::claim_invite`]) and the admin admits it
//! ([`Event::InviteClaimed`] → [`Client::accept_claim`]), see ADR 0005.
//! Plaintext bodies are refused.
//!
//! Extension points (see `docs/guides/adapting.md`):
//! - [`Store`]: bring your own storage backend.
//! - [`Signer`]: bring your own key storage (keychain, secure enclave).
//! - [`Transport`]: bring your own connection to the relay or peers.
//! - object types and payload formats are application-defined.

pub use kith_core::{
    Change, ChangeId, DeviceId, IdError, ObjectId, ObjectType, Scope, ScopeError, Signer,
    UnsignedChange,
};
pub use kith_crypto::{DeviceKey, GroupError, Groups};
#[cfg(feature = "automerge")]
pub use kith_merge::automerge_merger;
mod backup;
mod changes;
mod checks;
mod compact;
mod files;
mod frames;
mod invites;
mod mls;
mod org;
mod permissions;
mod plain;
mod requests;
mod sync;

pub use files::{FILE_TYPE, FileInfo, FileRef};

pub use compact::COMPACT_MIN_CHANGES;
pub use kith_core::membership::{CertChain, Invite, MembershipCert, Revocation};
pub use kith_core::policy::Retention;
pub use kith_core::policy::{POLICY_TYPE, Policy, PolicyOp, Role, policy_object_id};
use kith_core::snapshot;
pub use org::ORGS_KEY;

pub use kith_merge::{Materialized, MergeError, Merger};
pub use kith_store::{MemoryStore, Store, StoreError};

use kith_crypto::CommitOutcome;
use kith_crypto::sealed;
use kith_protocol::Frame;
use sync::Outer;

/// Most rejected changes kept (quarantined) per author; beyond that they are
/// dropped. Honest devices stay far below; it bounds what a misbehaving member can
/// make others store.
pub const MAX_QUARANTINE: usize = if cfg!(test) { 20 } else { 1000 };

/// Meta key of the revocation notices this device signed or was given (ADR 0024).
const REVOCATIONS_KEY: &str = "revocations";
/// One catch-up round moves at most this many changes in each direction and about
/// this many bytes (REQ-SYNC-005). A bigger difference takes several rounds, so a
/// large first sync stays under the relay's rate limits and an interrupted one
/// resumes with the next catch-up (what is stored is not asked for again).
const SYNC_BATCH_CHANGES: usize = 500;
const SYNC_BATCH_BYTES: usize = 2 * 1024 * 1024;
/// Most notices kept per org: what the relay takes in one announce (ADR 0013).
const MAX_HELD_NOTICES: usize = 256;

/// A claim waiting for [`Client::accept_claim`]: (KeyPackage, invite token, our nonce).
type PendingClaim = (Vec<u8>, [u8; 16], [u8; 32]);

/// Claims one invite may have waiting at once; more are refused, so a holder of a
/// leaked link cannot keep trying for a matching short code.
const MAX_CLAIMS_PER_INVITE: usize = 8;

/// Key under which the MLS state is kept in the [`Store`] (`Store::put_meta`).
pub const MLS_STATE_KEY: &str = "mls";

/// Library version (all kith crates are versioned together).
pub fn kith_core_version() -> &'static str {
    kith_core::VERSION
}

/// Client errors.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Storage failure.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Incoming change failed validation.
    #[error("rejected change: {0}")]
    Rejected(#[from] kith_core::ChangeError),
    /// Reconciliation failed locally.
    #[error(transparent)]
    Sync(#[from] kith_sync::SyncError),
    /// Merging an object's history failed.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// Object does not exist locally.
    #[error("unknown object {0}")]
    UnknownObject(ObjectId),
    /// MLS group operation failed (for example: not a member of the org yet).
    #[error(transparent)]
    Group(#[from] GroupError),
    /// Not a valid device ID.
    #[error(transparent)]
    Id(#[from] IdError),
    /// A backup could not be read (wrong passphrase, damaged, not a backup).
    #[error("backup: {0}")]
    InvalidBackup(String),
    /// Not all chunks of the file are on this device yet (how many are missing).
    #[error("file incomplete: {0} chunks missing; fetch it first")]
    FileIncomplete(usize),
    /// This device belongs to several orgs: say which one (`create_in`).
    #[error("several orgs: choose a scope with create_in")]
    AmbiguousScope,
    /// The policy does not allow this change (REQ-PERM-002).
    #[error("not allowed: {0}")]
    Forbidden(String),
    /// This device is not an admin of the org (or lacks the root key, for
    /// `grant_admin`).
    #[error("not an admin of {0}")]
    NotAdmin(String),
    /// An invite link or claim is invalid, expired or unknown.
    #[error("invite: {0}")]
    InvalidInvite(String),
    /// A document's JSON or merge patch is invalid (not JSON, or not an object).
    #[error("invalid document: {0}")]
    InvalidDocument(String),
    /// The secrets in the store can't be read with this device key (ADR 0021).
    #[error("stored state: {0}")]
    StoredState(String),
}

fn stored_state(e: kith_crypto::sealed::SealError) -> ClientError {
    ClientError::StoredState(e.to_string())
}

/// Connection to the relay (or a direct peer). Implemented per platform:
/// tokio WebSocket on native, browser WebSocket on web.
pub trait Transport {
    /// Send an encoded protocol frame.
    fn send(&mut self, frame: Frame) -> Result<(), String>;
}

/// The first frame to send after connecting to the relay.
pub fn hello_frame(signer: &dyn Signer) -> Frame {
    Frame::Hello {
        version: kith_protocol::PROTOCOL_VERSION,
        device: signer.device_id().to_hex(),
    }
}

/// The answer to the relay's [`Frame::Challenge`]: a signature proving this
/// device owns its key (REQ-RELAY-004).
pub fn auth_frame(signer: &dyn Signer, nonce: &str) -> Frame {
    let msg = kith_protocol::auth_message(&signer.device_id().to_hex(), nonce);
    Frame::Auth {
        signature: hex_encode(&signer.sign(&msg)),
    }
}

/// Frame announcing `org` with a membership `proof` (`CertChain::to_hex`, or empty
/// while joining) after authenticating. Usually [`Client::announce_frame`].
pub fn announce_frame(org: &str, proof: &str) -> Frame {
    Frame::Announce {
        orgs: vec![kith_protocol::Membership {
            org: org.into(),
            proof: proof.into(),
            always_on: false,
            revoked: vec![],
        }],
    }
}

/// What [`Client::claim_invite`] returns.
#[derive(Debug)]
pub struct Claim {
    /// The org the invite is for: connect to `relay` and announce it first.
    pub org: String,
    /// The relay URL from the invite.
    pub relay: String,
    /// The claim to send (an `invite-claim` frame). The short code to show follows
    /// as [`Event::ClaimCode`] once the admin answers.
    pub frame: Frame,
}

/// Result of [`Client::handle_frame`].
#[derive(Debug)]
pub struct Handled {
    /// What the frame meant for the app.
    pub event: Event,
    /// Frames to send to the relay in answer (catch-up replies); usually empty.
    pub replies: Vec<Frame>,
}

impl Handled {
    fn event(event: Event) -> Self {
        Self {
            event,
            replies: vec![],
        }
    }

    /// A peer's message was refused: report it and do nothing else.
    fn rejected(org: &str, from: &str, reason: impl Into<String>) -> Self {
        Self::event(Event::Rejected {
            org: org.into(),
            from: from.into(),
            reason: reason.into(),
        })
    }
}

/// What a frame from the relay meant for this client.
#[derive(Debug)]
pub enum Event {
    /// A peer's change was valid and handled. `is_new` is false if it was already stored.
    Received {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// The change.
        change: Box<Change>,
        /// True if the change was not stored before.
        is_new: bool,
    },
    /// A peer's message was refused (undecodable, not decryptable, bad hash or
    /// signature, unencrypted). Nothing was stored.
    Rejected {
        /// Organization.
        org: String,
        /// Sender device (hex).
        from: String,
        /// Why.
        reason: String,
    },
    /// Devices currently online in an org.
    Presence {
        /// Organization.
        org: String,
        /// Online devices (hex).
        online: Vec<String>,
    },
    /// Which devices a broadcast of ours reached.
    Receipt {
        /// Devices that received it.
        delivered: Vec<String>,
    },
    /// The relay refused something.
    RelayError {
        /// Machine-readable code.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// We answered a round of a peer's catch-up request (set reconciliation).
    SyncServed {
        /// The requesting device (hex).
        from: String,
    },
    /// Our catch-up request is reconciled: we sent `from` the `sending` changes it
    /// lacks and asked for the `wanting` changes we lack (they arrive as
    /// [`Event::SyncReceived`]). Both zero: we are in sync with that peer.
    SyncCompared {
        /// The peer (hex).
        from: String,
        /// Changes we sent.
        sending: usize,
        /// Changes we asked for.
        wanting: usize,
    },
    /// A peer sent changes for catch-up (after [`Event::SyncCompared`], or as the
    /// partner of a peer's catch-up).
    SyncReceived {
        /// The sending device (hex).
        from: String,
        /// Changes that were new and are now stored.
        stored: usize,
        /// Changes that were already known.
        known: usize,
        /// Changes refused (undecodable, bad hash or signature).
        rejected: usize,
        /// Changes the peer asked us to send back (we replied with them).
        requested: usize,
    },
    /// The admin answered our invite claim: show `code`; the admin's screen shows
    /// the same in [`Event::InviteClaimed`] (REQ-INV-003). [`Event::Joined`]
    /// follows once it accepts.
    ClaimCode {
        /// Organization.
        org: String,
        /// The admin that answered (hex); only its Welcome is accepted.
        from: String,
        /// The short code to show.
        code: String,
    },
    /// A device claimed one of our invites with a valid proof (REQ-INV-002). To
    /// admit it call [`Client::accept_claim`] (after comparing `code` with the new
    /// device's screen, if the app wants that, REQ-INV-003); otherwise
    /// [`Client::reject_claim`].
    InviteClaimed {
        /// Organization.
        org: String,
        /// The claiming device (hex).
        from: String,
        /// The short code its screen shows.
        code: String,
    },
    /// We received a new membership certificate (for example admin rights) and
    /// re-announced with it.
    CertificateUpdated {
        /// Organization.
        org: String,
        /// True if we are now an admin.
        admin: bool,
    },
    /// This device joined `org`'s group from a Welcome; the reply asks a peer
    /// for the history (catch-up).
    Joined {
        /// Organization.
        org: String,
    },
    /// A commit changed `org`'s group: a member was added or removed, or keys rotated.
    GroupChanged {
        /// Organization.
        org: String,
        /// New epoch.
        epoch: u64,
        /// True if this device was removed: it can no longer read or send in `org`.
        removed: bool,
    },
    /// This device missed commits of `org`'s group; the reply asks `from` for them.
    EpochBehind {
        /// Organization.
        org: String,
        /// The peer whose message showed we are behind (hex).
        from: String,
    },
    /// A peer that was behind got the commits it missed from us (`commits`), or,
    /// if our log does not reach back far enough, a request to be re-added.
    CommitsServed {
        /// Organization.
        org: String,
        /// The peer (hex).
        to: String,
        /// Commits sent.
        commits: usize,
        /// True if we asked the peer to send a KeyPackage instead.
        readd_needed: bool,
    },
    /// We applied commits we had missed (REQ-ENC-002); the reply restarts data
    /// catch-up with that peer.
    CommitsApplied {
        /// Organization.
        org: String,
        /// The sending peer (hex).
        from: String,
        /// Commits applied.
        applied: usize,
        /// Our epoch now.
        epoch: u64,
    },
    /// A peer is too far behind for our log: we asked to be re-added and sent it a
    /// fresh KeyPackage (REQ-ENC-004).
    ReAddRequested {
        /// Organization.
        org: String,
        /// The peer that will re-add us (hex).
        from: String,
    },
    /// We sent a peer file chunks it asked for (and told it which we lack).
    ChunksServed {
        /// The asking device (hex).
        to: String,
        /// Chunks sent.
        sent: usize,
        /// Chunks we do not have.
        missing: usize,
    },
    /// File chunks arrived and were verified and stored; `ready` lists files that
    /// are now complete (`read_file` works).
    FileChunks {
        /// The sending device (hex).
        from: String,
        /// Chunks stored.
        stored: usize,
        /// Files now complete.
        ready: Vec<ObjectId>,
    },
    /// The asked peer lacks some chunks we want. The client then asks the file's
    /// author directly (once); if that fails too, try again later.
    ChunksMissing {
        /// The peer (hex).
        from: String,
        /// How many it lacks.
        count: usize,
    },
    /// We (the subgroup's owner) added `device` to subgroup `org` (`org/name`).
    MemberAdded {
        /// Group key (`org/name`).
        org: String,
        /// The device (hex).
        device: String,
    },
    /// We re-added `device`, which had fallen too far behind (REQ-ENC-004).
    MemberReAdded {
        /// Organization.
        org: String,
        /// The device (hex).
        device: String,
    },
    /// Two members committed in the same epoch and the group forked (ADR 0004).
    /// If `we_win` is false this device asked `peer` (on the winning branch) to
    /// re-add it; otherwise it showed `peer` the winning commit so `peer`'s branch
    /// rejoins. Data sent on the losing branch arrives again through catch-up.
    Fork {
        /// Organization.
        org: String,
        /// The peer on the other branch (hex).
        peer: String,
        /// True if our branch won.
        we_win: bool,
    },
    /// A frame this client has nothing to do with.
    Ignored,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn direct(org: &str, to: &str, body: Vec<u8>) -> Frame {
    Frame::Direct {
        org: org.into(),
        to: to.into(),
        body,
    }
}

/// A device's view of the organizations it belongs to.
pub struct Client<S: Store, K: Signer = DeviceKey> {
    key: K,
    /// Seals the org and MLS state before they reach the store (ADR 0021).
    storage_key: zeroize::Zeroizing<[u8; 32]>,
    store: S,
    groups: Groups,
    /// Per org: the epoch at which we last asked to be re-added after losing a
    /// fork, so one fork sends one request, not one per message.
    readd_asked: std::collections::HashMap<String, u64>,
    /// Per scope: our running catch-up reconciliation (one at a time).
    /// The peer it runs with: known for a `Direct` request, otherwise the first
    /// device that answers; other devices' answers are ignored.
    reconciling: std::collections::HashMap<String, (kith_sync::Reconciliation, Option<String>)>,
    /// (group, device) → our epoch when we last sent that device the commits it
    /// missed unasked, so a message claiming an old epoch triggers that once per
    /// epoch, not every time (RAM).
    helped: std::collections::HashMap<(String, String), u64>,
    /// Subgroups we sent our KeyPackage to the owner for (RAM; `sync_request_frames` retries).
    kp_asked: std::collections::HashSet<String>,
    /// Orgs we asked a peer to re-add us to after a restore (RAM).
    rejoin_asked: std::collections::HashSet<String>,
    /// Groups we sent a KeyPackage for (re-add, rejoin, subgroup) → the device we
    /// sent it to. Only that device's Welcome for that group is accepted (RAM).
    welcome_from: std::collections::HashMap<String, DeviceId>,
    /// Orgs we claimed an invite for → the device whose Welcome we accept: the
    /// issuing member for own-device invites, then the admin that answered the
    /// claim (RAM; after a restart the certificate chain alone decides).
    joining: std::collections::HashMap<String, Option<DeviceId>>,
    /// Orgs we claimed an invite for → (invite, our KeyPackage), to check the
    /// admin's nonce and derive the short code (RAM).
    claiming: std::collections::HashMap<String, (Invite, Vec<u8>)>,
    /// Announce as an always-on client (REQ-SYNC-006).
    always_on: bool,
    /// Fetch files' chunks as soon as their `kith.file` arrives.
    fetch_files: bool,
    /// Chunks we asked for, per file (RAM).
    wanted_chunks: std::collections::HashMap<ObjectId, std::collections::HashSet<[u8; 32]>>,
    /// Files whose author we already asked directly after a peer lacked chunks.
    asked_author: std::collections::HashSet<ObjectId>,
    /// Certificates, root keys, issued invites.
    orgs: org::Orgs,
    /// Revocation notices this device signed (REQ-INV-004); repeated on every
    /// announce so a restarted relay learns them again.
    revocations: Vec<Revocation>,
    /// Valid invite claims waiting for [`Client::accept_claim`]: (org, device) →
    /// (KeyPackage, invite token, our nonce). RAM only: after a restart the device
    /// claims again.
    claims: std::collections::HashMap<(String, String), PendingClaim>,
    /// Per org: the policy folded from its policy object (phase 6).
    policies: std::collections::BTreeMap<String, Policy>,
    /// Stored changes the policy does not allow (hidden from history, merge, sync).
    invalid: std::collections::HashSet<ChangeId>,
    /// Quarantined changes per author (capped at [`MAX_QUARANTINE`]).
    quarantined: std::collections::HashMap<DeviceId, usize>,
    /// IDs of changes that accepted snapshots cover (REQ-DATA-005, ADR 0026): deleted
    /// from the store (except creations) and never stored again.
    covered: std::collections::HashSet<ChangeId>,
}

impl<S: Store, K: Signer> Client<S, K> {
    /// Create a client from a signer and a store. Loads the MLS group state from
    /// the store if there is one.
    pub fn new(key: K, store: S) -> Result<Self, ClientError> {
        let storage_key = zeroize::Zeroizing::new(sealed::storage_key(&key).map_err(stored_state)?);
        let open = |name: &str| -> Result<Option<Vec<u8>>, ClientError> {
            match store.get_meta(name)? {
                Some(v) => Ok(Some(
                    sealed::open(&storage_key, name, &v).map_err(stored_state)?,
                )),
                None => Ok(None),
            }
        };
        let groups = match open(MLS_STATE_KEY)? {
            Some(bytes) => Groups::from_bytes(&bytes)?,
            None => Groups::new(),
        };
        let revocations = match store.get_meta(REVOCATIONS_KEY)? {
            Some(bytes) => String::from_utf8_lossy(&bytes)
                .lines()
                .filter_map(|l| Revocation::from_hex(l).ok())
                .collect(),
            None => vec![],
        };
        let orgs = match open(ORGS_KEY)? {
            Some(bytes) => org::Orgs::from_bytes(&bytes).map_err(GroupError::Corrupt)?,
            None => org::Orgs::default(),
        };
        Self {
            key,
            storage_key,
            store,
            groups,
            readd_asked: Default::default(),
            reconciling: Default::default(),
            helped: Default::default(),
            kp_asked: Default::default(),
            rejoin_asked: Default::default(),
            welcome_from: Default::default(),
            joining: Default::default(),
            claiming: Default::default(),
            always_on: false,
            fetch_files: false,
            wanted_chunks: Default::default(),
            asked_author: Default::default(),
            orgs,
            revocations,
            claims: Default::default(),
            policies: Default::default(),
            invalid: Default::default(),
            quarantined: Default::default(),
            covered: Default::default(),
        }
        .with_policies()
    }

    fn with_policies(mut self) -> Result<Self, ClientError> {
        self.refresh_policies()?;
        self.upgrade_policies()?;
        Ok(self)
    }

    /// Orgs created before the genesis had to be signed by the root key have a
    /// policy without a valid genesis, and before that, members were not named in
    /// the policy. The device holding the root key upgrades them: it adds the
    /// root-signed genesis and names the current group members as editors. The new
    /// changes reach the others through catch-up.
    fn upgrade_policies(&mut self) -> Result<(), ClientError> {
        let legacy: Vec<(String, [u8; 32])> = self
            .orgs
            .0
            .iter()
            .filter_map(|(org, st)| Some((org.clone(), st.root?)))
            .filter(|(org, _)| self.policies.get(org).is_some_and(|p| p.creator.is_none()))
            .collect();
        for (org, root) in legacy {
            let root = DeviceKey::from_secret_bytes(&root);
            let genesis = PolicyOp::Genesis {
                admin: MembershipCert::issue(
                    &root,
                    root.device_id(),
                    self.device_id(),
                    true,
                    now_ms(),
                ),
            };
            self.policy_commit_by(&org, genesis, Some(&root))?;
            let members = self.groups.members(&org).unwrap_or_default();
            for m in members {
                let unnamed = self
                    .policies
                    .get(&org)
                    .is_some_and(|p| p.role_of(&m).is_none() && !p.revoked.contains(&m));
                if unnamed {
                    let op = PolicyOp::SetRole {
                        device: m,
                        role: Role::Editor,
                        cert: None,
                    };
                    self.policy_commit(&org, op)?;
                }
            }
        }
        Ok(())
    }

    /// The signer this client was created with (for `DeviceKey`: read the
    /// secret seed to persist it, see `DeviceKey::secret_bytes`).
    pub fn signer(&self) -> &K {
        &self.key
    }

    /// Access the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    fn commit(
        &mut self,
        scope: Scope,
        object_id: ObjectId,
        object_type: ObjectType,
        parents: Vec<ChangeId>,
        payload: Vec<u8>,
    ) -> Result<Change, ClientError> {
        let change = Change::sign(
            UnsignedChange {
                scope,
                object_id,
                object_type,
                parents,
                timestamp_ms: now_ms(),
                payload,
            },
            &self.key,
        );
        self.check_allowed(&change)?;
        self.store.put(change.clone())?;
        Ok(change)
    }
}

/// Marker returned by `group_in` for subgroups of the org that we are not in.
const SUBGROUP_NOT_OURS: &str = "";

/// True if `group` is `org` itself or one of its subgroups (`org/name`).
fn in_org(org: &str, group: &str) -> bool {
    group == org
        || group
            .strip_prefix(org)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The first changes of `changes` (oldest first) that fit one round, and whether
/// some were left out (REQ-SYNC-005).
fn batch(changes: Vec<Change>) -> (Vec<Change>, bool) {
    let mut bytes = 0;
    let mut n = 0;
    for c in &changes {
        bytes += kith_store::codec::encode_change(c).len();
        if n >= SYNC_BATCH_CHANGES || (n > 0 && bytes > SYNC_BATCH_BYTES) {
            break;
        }
        n += 1;
    }
    let cut = n < changes.len();
    let mut changes = changes;
    changes.truncate(n);
    (changes, cut)
}

fn org_scope(org: &str) -> Result<Scope, ClientError> {
    Scope::parse(org).map_err(|e| ClientError::Forbidden(e.to_string()))
}

/// JSON documents (REQ-DATA-004): objects whose changes are Automerge changes,
/// read and written as JSON. Concurrent patches of different keys both survive;
/// the same key gets the same winner on every device.
#[cfg(feature = "automerge")]
impl<S: Store, K: Signer> Client<S, K> {
    /// Create a document from a JSON object, in the default scope (see
    /// [`Client::create`]). Broadcast the returned change like any other.
    pub fn create_document(&mut self, ty: ObjectType, json: &str) -> Result<Change, ClientError> {
        let scope = self.default_scope()?;
        self.create_document_in(scope, ty, json)
    }

    /// [`Self::create_document`] in `scope`.
    pub fn create_document_in(
        &mut self,
        scope: Scope,
        ty: ObjectType,
        json: &str,
    ) -> Result<Change, ClientError> {
        let patch = parse_object(json)?;
        let mut doc = automerge_merger::automerge::AutoCommit::new();
        let payload =
            automerge_merger::author(&mut doc, |d| automerge_merger::merge_patch(d, &patch))?
                // An empty object still needs a change to exist.
                .unwrap_or_default();
        self.create_in(scope, ty, payload)
    }

    /// Change a document with an RFC 7396 JSON merge patch (`null` removes a key,
    /// objects merge, other values replace). `None` if the patch changes nothing.
    pub fn update_document(
        &mut self,
        object: ObjectId,
        patch: &str,
    ) -> Result<Option<Change>, ClientError> {
        let patch = parse_object(patch)?;
        let mut doc = self
            .materialize(&object, &automerge_merger::AutomergeMerger)?
            .state;
        match automerge_merger::author(&mut doc, |d| automerge_merger::merge_patch(d, &patch))? {
            Some(payload) => Ok(Some(self.edit(object, payload)?)),
            None => Ok(None),
        }
    }

    /// The merged state of a document as JSON, all forks included.
    pub fn document_json(&self, object: &ObjectId) -> Result<String, ClientError> {
        let doc = self
            .materialize(object, &automerge_merger::AutomergeMerger)?
            .state;
        Ok(automerge_merger::to_json(&doc).to_string())
    }
}

#[cfg(feature = "automerge")]
fn parse_object(json: &str) -> Result<serde_json::Value, ClientError> {
    match serde_json::from_str(json) {
        Ok(v @ serde_json::Value::Object(_)) => Ok(v),
        Ok(_) => Err(ClientError::InvalidDocument("must be a JSON object".into())),
        Err(e) => Err(ClientError::InvalidDocument(e.to_string())),
    }
}

/// Wall-clock time in milliseconds since the Unix epoch.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Wall-clock time in milliseconds since the Unix epoch.
/// `std::time::SystemTime::now()` panics on wasm32-unknown-unknown, so use the JS clock.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

#[cfg(test)]
mod tests;
