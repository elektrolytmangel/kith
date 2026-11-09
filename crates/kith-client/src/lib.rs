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
mod compact;
mod files;
mod org;
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

    /// This device's ID.
    pub fn device_id(&self) -> DeviceId {
        self.key.device_id()
    }

    /// Create a new object with an initial payload, in the default scope: the org
    /// this device belongs to, or `local` (never synced) before it joins one. With
    /// several orgs use [`Self::create_in`]. Fails with [`ClientError::Forbidden`]
    /// if the org's policy does not let this device write objects of type `ty`.
    pub fn create(&mut self, ty: ObjectType, payload: Vec<u8>) -> Result<Change, ClientError> {
        let scope = self.default_scope()?;
        self.create_in(scope, ty, payload)
    }

    /// Create a new object in `scope` (an org this device belongs to, or `local`).
    pub fn create_in(
        &mut self,
        scope: Scope,
        ty: ObjectType,
        payload: Vec<u8>,
    ) -> Result<Change, ClientError> {
        if ty.as_str() == POLICY_TYPE {
            return Err(ClientError::Forbidden("use the policy methods".into()));
        }
        if snapshot::is_snapshot(&payload) {
            return Err(ClientError::Forbidden(
                "payloads starting with the snapshot marker are reserved".into(),
            ));
        }
        self.check_scope(&scope)?;
        self.commit(scope, ObjectId::random(), ty, vec![], payload)
    }

    /// The scope `create` uses: the only org this device is a member of, else `local`.
    pub fn default_scope(&self) -> Result<Scope, ClientError> {
        let mut orgs = self
            .orgs
            .0
            .iter()
            .filter(|(_, st)| st.chain.is_some())
            .map(|(o, _)| o);
        match (orgs.next(), orgs.next()) {
            (None, _) => Ok(Scope::local()),
            (Some(org), None) => {
                Ok(Scope::parse(org).map_err(|e| ClientError::Forbidden(e.to_string()))?)
            }
            _ => Err(ClientError::AmbiguousScope),
        }
    }

    /// `local`, or an org (or subgroup of one) this device is a member of.
    fn check_scope(&self, scope: &Scope) -> Result<(), ClientError> {
        if scope.subgroup_name().is_some() && !self.groups.is_member(scope.as_str()) {
            return Err(ClientError::Forbidden(format!(
                "not a member of subgroup {scope}"
            )));
        }
        match scope.org_id() {
            None => Ok(()),
            Some(org)
                if self
                    .orgs
                    .0
                    .get(&org.to_hex())
                    .is_some_and(|s| s.chain.is_some()) =>
            {
                Ok(())
            }
            Some(org) => Err(ClientError::Forbidden(format!("not a member of org {org}"))),
        }
    }

    /// Append a change to an existing object, building on its current heads.
    /// Never blocks on a lock: concurrent edits become a fork that the merge
    /// layer resolves (REQ-DATA-004).
    pub fn edit(&mut self, object: ObjectId, payload: Vec<u8>) -> Result<Change, ClientError> {
        let (ty, scope) = self.object_meta(&object)?;
        if ty.as_str() == POLICY_TYPE {
            return Err(ClientError::Forbidden("use the policy methods".into()));
        }
        if snapshot::is_snapshot(&payload) {
            return Err(ClientError::Forbidden(
                "payloads starting with the snapshot marker are reserved".into(),
            ));
        }
        let parents = self.valid_heads(&object)?;
        self.commit(scope, object, ty, parents, payload)
    }

    /// Type and scope of an object, from any change of it we still store (a creation
    /// change is always kept, see [`Self::compact`]).
    fn object_meta(&self, object: &ObjectId) -> Result<(ObjectType, Scope), ClientError> {
        self.store
            .history(object)?
            .into_iter()
            .find(|c| !self.invalid.contains(&c.change_id))
            .map(|c| (c.body.object_type, c.body.scope))
            .ok_or(ClientError::UnknownObject(*object))
    }

    /// Heads of an object among the changes the policy allows.
    fn valid_heads(&self, object: &ObjectId) -> Result<Vec<ChangeId>, ClientError> {
        let hist = self.merge_history(object)?;
        let mut heads: Vec<ChangeId> = hist.iter().map(|c| c.change_id).collect();
        for c in &hist {
            heads.retain(|h| !c.body.parents.contains(h));
        }
        heads.sort();
        Ok(heads)
    }

    /// Validate and store a change received from a peer.
    /// Returns `true` if it was new.
    /// A change with a bad hash or signature is refused. Every other change is
    /// stored, and the policy decides whether it counts (REQ-PERM-002): one the
    /// author was not allowed to make, or that builds on such a change, returns
    /// [`ClientError::Forbidden`] and is kept out of history, merging and new
    /// edits. It is still passed on in catch-up, so every device sees it and reaches
    /// the same verdict, and a later policy change (a late grant) can make it count.
    /// Policy changes trigger a re-check of everything stored.
    pub fn receive(&mut self, change: Change) -> Result<bool, ClientError> {
        change.verify()?;
        // Folded into a snapshot already (creations are always kept, ADR 0026).
        if self.covered.contains(&change.change_id) && !change.is_creation() {
            return Ok(false);
        }
        // Only orgs we belong to; an object never moves between scopes.
        self.check_scope(&change.body.scope)?;
        if let Some(first) = self.store.history(&change.body.object_id)?.first()
            && first.body.scope != change.body.scope
        {
            return Err(ClientError::Forbidden(
                "object belongs to another scope".into(),
            ));
        }
        // Parents are changes of the same object.
        for p in &change.body.parents {
            if let Some(parent) = self.store.get(p)?
                && parent.body.object_id != change.body.object_id
            {
                return Err(ClientError::Forbidden(format!(
                    "parent {p} belongs to another object"
                )));
            }
        }
        let full = self.quarantined.get(&change.author).copied().unwrap_or(0) >= MAX_QUARANTINE;
        if change.body.object_type.as_str() == POLICY_TYPE {
            // Policy changes by non-admins never count (members only link their own
            // devices). Once we have the org's policy, others are not kept (each
            // kept one re-folds the policy), except the root-signed genesis; before
            // that, up to the cap. A refused one comes again with the next catch-up.
            let org_id = change.body.scope.org_id();
            let policy = org_id
                .and_then(|o| self.policies.get(&o.to_hex()))
                .filter(|p| p.creator.is_some());
            let link = matches!(
                PolicyOp::decode(&change.body.payload),
                Ok(PolicyOp::LinkDevice { .. })
            );
            let admin = policy.is_some_and(|p| match p.role_of(&change.author) {
                Some(Role::Admin) => true,
                Some(_) => link,
                None => false,
            }) || org_id.is_some_and(|o| o == change.author);
            if (full || policy.is_some()) && !admin {
                return Err(ClientError::Forbidden(
                    "too many rejected changes from this device".into(),
                ));
            }
            let new = self.store.put(change)?;
            if new {
                self.refresh_policies()?;
            }
            return Ok(new);
        }
        if let Err(e) = self.check_allowed(&change) {
            // Kept (quarantined) so every device decides the same, up to a cap per
            // author so a misbehaving member cannot fill our storage (REQ-RELAY-006).
            if !full && self.store.put(change.clone())? {
                *self.quarantined.entry(change.author).or_default() += 1;
            }
            self.invalid.insert(change.change_id);
            return Err(e);
        }
        let new = self.store.put(change.clone())?;
        if new && snapshot::is_snapshot(&change.body.payload) {
            self.apply_snapshot(&change)?;
        }
        Ok(new)
    }

    fn check_allowed(&self, change: &Change) -> Result<(), ClientError> {
        if let Some(p) = change
            .body
            .parents
            .iter()
            .find(|p| self.invalid.contains(p))
        {
            return Err(ClientError::Forbidden(format!(
                "builds on rejected change {p}"
            )));
        }
        // The policy of the org the change belongs to.
        let org = change.body.scope.org_id().map(|o| o.to_hex());
        if snapshot::is_snapshot(&change.body.payload) {
            // Only admins fold history (ADR 0026); a snapshot an admin made before being
            // restricted stays valid like their other seen changes (`kept`).
            if org.is_none() || snapshot::Snapshot::decode(&change.body.payload).is_none() {
                return Err(ClientError::Forbidden("malformed snapshot".into()));
            }
            if let Some(policy) = org.as_ref().and_then(|o| self.policies.get(o))
                && policy.creator.is_some()
                && !policy.is_admin_device(&change.author)
                && !policy
                    .kept
                    .get(&change.author)
                    .is_some_and(|k| k.contains(&change.change_id))
            {
                return Err(ClientError::Forbidden(
                    "only admins may create snapshots".into(),
                ));
            }
        }
        if let Some(policy) = org.as_ref().and_then(|o| self.policies.get(o))
            && policy.creator.is_some()
            && !policy.allows(change)
        {
            return Err(ClientError::Forbidden(format!(
                "{} may not write {} in {}",
                change.author,
                change.body.object_type.as_str(),
                org.unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Re-fold every org's policy and re-check all stored changes against it.
    /// Called on start and whenever a policy change arrives (they are rare).
    fn refresh_policies(&mut self) -> Result<(), ClientError> {
        let mut policies = std::collections::BTreeMap::new();
        for org in self.orgs.0.keys() {
            let Ok(org_id) = DeviceId::from_hex(org) else {
                continue;
            };
            let hist = self.store.history(&policy_object_id(&org_id))?;
            if !hist.is_empty() {
                policies.insert(org.clone(), Policy::fold(&org_id, &hist));
            }
        }
        self.policies = policies;
        self.invalid.clear();
        self.quarantined.clear();
        if self.policies.is_empty() {
            return Ok(());
        }
        // Parents before children (per object), so a rejected parent rejects its children.
        let mut all = Vec::new();
        for id in self.store.all_ids()? {
            if let Some(c) = self.store.get(&id)? {
                all.push(c);
            }
        }
        all.sort_by_key(|c| (c.body.timestamp_ms, c.change_id));
        let mut changed = true;
        while changed {
            changed = false;
            for c in &all {
                if self.invalid.contains(&c.change_id) || c.body.object_type.as_str() == POLICY_TYPE
                {
                    continue;
                }
                if self.check_allowed(c).is_err() {
                    self.invalid.insert(c.change_id);
                    changed = true;
                }
            }
        }
        // Quarantine counts per author: rejected changes and policy changes that did not count.
        for c in &all {
            let rejected_policy = c.body.object_type.as_str() == POLICY_TYPE
                && !self
                    .policies
                    .values()
                    .any(|p| p.accepted.contains(&c.change_id));
            if self.invalid.contains(&c.change_id) || rejected_policy {
                *self.quarantined.entry(c.author).or_default() += 1;
            }
        }
        // Snapshots (re)apply: delete what they cover, also what an earlier run missed.
        self.covered.clear();
        for c in &all {
            if snapshot::is_snapshot(&c.body.payload) {
                self.apply_snapshot(c)?;
            }
        }
        Ok(())
    }

    // ---- permissions (phase 6, ADR 0006) ----

    /// The current policy of `org`, if this device has it.
    pub fn policy(&self, org: &str) -> Option<&Policy> {
        self.policies.get(org)
    }

    /// A device's role in `org` (`None`: revoked or not a member). Devices the
    /// policy does not name have no role; without a policy everyone is an editor.
    pub fn role_of(&self, org: &str, device: &str) -> Result<Option<Role>, ClientError> {
        let d = DeviceId::from_hex(device)?;
        Ok(self
            .policies
            .get(org)
            .map_or(Some(Role::Editor), |p| p.role_of(&d)))
    }

    /// Set a member's role. Raising to admin needs the org root key (only the
    /// creator can); lowering keeps the member's changes this device has seen.
    /// Broadcast the returned change like any other.
    pub fn set_role(&mut self, org: &str, device: &str, role: Role) -> Result<Change, ClientError> {
        let d = DeviceId::from_hex(device)?;
        let current = self.role_of(org, device)?;
        let op = if current.is_some_and(|c| role < c) {
            PolicyOp::Restrict {
                device: d,
                role: Some(role),
                keep: self.changes_by_user(org, &d)?,
            }
        } else {
            let cert = if role == Role::Admin {
                Some(self.root_admin_cert(org, d)?)
            } else {
                None
            };
            PolicyOp::SetRole {
                device: d,
                role,
                cert,
            }
        };
        self.policy_commit(org, op)
    }

    /// Set the minimum role that may write objects of `object_type` in `org`.
    /// Broadcast the returned change.
    pub fn set_write_rule(
        &mut self,
        org: &str,
        object_type: &str,
        write: Role,
    ) -> Result<Change, ClientError> {
        self.policy_commit(
            org,
            PolicyOp::SetRule {
                object_type: object_type.into(),
                write,
            },
        )
    }

    /// Revoke a device's write access in `org` (REQ-INV-004). Changes of it that
    /// this device has already seen stay valid; all others are rejected everywhere.
    /// Usually via [`Self::remove_member`], which also removes it from the group.
    pub fn revoke(&mut self, org: &str, device: &str) -> Result<Change, ClientError> {
        let d = DeviceId::from_hex(device)?;
        let keep = self.changes_by_user(org, &d)?;
        self.policy_commit(
            org,
            PolicyOp::Restrict {
                device: d,
                role: None,
                keep,
            },
        )
    }

    /// Create read-restricted subgroup `name` of `org` with `members` (hex; this
    /// device is always included) (REQ-PERM-003). Admins only. This device becomes
    /// the subgroup's owner: it runs its MLS group and must be online for members to
    /// be added (they send it their KeyPackage once they see the policy). Data in
    /// scope `org/name` ([`Scope::subgroup`]) only reaches members. Send the frames.
    pub fn create_subgroup(
        &mut self,
        org: &str,
        name: &str,
        members: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        Scope::subgroup(&org_id, name).map_err(|e| ClientError::Forbidden(e.to_string()))?;
        if self
            .policies
            .get(org)
            .is_some_and(|p| p.subgroup(name).is_some())
        {
            return Err(ClientError::Forbidden(format!("subgroup {name} exists")));
        }
        self.set_subgroup_members(org, name, members)
    }

    /// Replace the members of subgroup `name` (hex IDs; admins only). Removed
    /// members keep the subgroup changes this device has seen; the owner removes them
    /// from the MLS group, so they cannot read anything new. Send the frames.
    pub fn set_subgroup_members(
        &mut self,
        org: &str,
        name: &str,
        members: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        let scope =
            Scope::subgroup(&org_id, name).map_err(|e| ClientError::Forbidden(e.to_string()))?;
        let mut list: Vec<DeviceId> = members
            .iter()
            .map(|m| DeviceId::from_hex(m))
            .collect::<Result<_, _>>()?;
        let me = self.device_id();
        let owner = self
            .policies
            .get(org)
            .and_then(|p| p.subgroup_owners.get(name).copied())
            .unwrap_or(me);
        for d in [me, owner] {
            if !list.contains(&d) {
                list.push(d);
            }
        }
        list.sort();
        list.dedup();
        // Changes by members being removed that we have seen stay valid.
        let mut keep = vec![];
        for id in self.store.scope_ids(&scope)? {
            if !self.invalid.contains(&id)
                && let Some(c) = self.store.get(&id)?
                && !list.contains(&c.author)
            {
                keep.push(id);
            }
        }
        let change = self.policy_commit(
            org,
            PolicyOp::SetSubgroup {
                name: name.into(),
                members: list,
                keep,
            },
        )?;
        let mut frames = vec![self.broadcast_frame(org, &change)?];
        frames.extend(self.subgroup_tasks()?);
        Ok(frames)
    }

    /// Members (hex) of subgroup `name` of `org` per the policy, if it exists.
    pub fn subgroup_members(&self, org: &str, name: &str) -> Option<Vec<String>> {
        self.policies
            .get(org)?
            .subgroup(name)
            .map(|m| m.iter().map(DeviceId::to_hex).collect())
    }

    /// Subgroups of `org` this device can read (it is in their MLS group).
    pub fn my_subgroups(&self, org: &str) -> Vec<String> {
        self.groups
            .orgs()
            .into_iter()
            .filter_map(|g| {
                let name = g.strip_prefix(org)?.strip_prefix('/')?.to_string();
                self.groups.is_member(&g).then_some(name)
            })
            .collect()
    }

    /// Changes by `device` and by the devices linked to it (one user, ADR 0011).
    fn changes_by_user(&self, org: &str, device: &DeviceId) -> Result<Vec<ChangeId>, ClientError> {
        let mut out = self.changes_by(device)?;
        for linked in self
            .policies
            .get(org)
            .map_or(vec![], |p| p.linked_to(device))
        {
            out.extend(self.changes_by(&linked)?);
        }
        out.sort();
        Ok(out)
    }

    fn changes_by(&self, device: &DeviceId) -> Result<Vec<ChangeId>, ClientError> {
        let mut out = Vec::new();
        for id in self.store.all_ids()? {
            if !self.invalid.contains(&id)
                && let Some(c) = self.store.get(&id)?
                && c.author == *device
            {
                out.push(id);
            }
        }
        out.sort();
        Ok(out)
    }

    fn root_admin_cert(&self, org: &str, device: DeviceId) -> Result<MembershipCert, ClientError> {
        let root = self
            .orgs
            .0
            .get(org)
            .and_then(|s| s.root)
            .ok_or_else(|| ClientError::NotAdmin(org.into()))?;
        let root = DeviceKey::from_secret_bytes(&root);
        Ok(MembershipCert::issue(
            &root,
            root.device_id(),
            device,
            true,
            now_ms(),
        ))
    }

    /// Append `op` to `org`'s policy object. Fails unless the op counts (we are an
    /// admin and it is valid), so a refused op never leaves the device.
    fn policy_commit(&mut self, org: &str, op: PolicyOp) -> Result<Change, ClientError> {
        self.policy_commit_by(org, op, None)
    }

    /// [`Self::policy_commit`], signed by the org root key `root` if given (the
    /// genesis), else by this device.
    fn policy_commit_by(
        &mut self,
        org: &str,
        op: PolicyOp,
        root: Option<&DeviceKey>,
    ) -> Result<Change, ClientError> {
        let signer: &dyn Signer = match root {
            Some(r) => r,
            None => &self.key,
        };
        let org_id = DeviceId::from_hex(org)?;
        let pid = policy_object_id(&org_id);
        let parents = self.store.heads(&pid)?;
        let change = Change::sign(
            UnsignedChange {
                scope: Scope::org(&org_id),
                object_id: pid,
                object_type: ObjectType::new(POLICY_TYPE),
                parents,
                timestamp_ms: now_ms(),
                payload: op.encode(),
            },
            signer,
        );
        let mut hist = self.store.history(&pid)?;
        hist.push(change.clone());
        if !Policy::fold(&org_id, &hist)
            .accepted
            .contains(&change.change_id)
        {
            return Err(ClientError::NotAdmin(org.into()));
        }
        self.store.put(change.clone())?;
        self.refresh_policies()?;
        Ok(change)
    }

    // ---- organizations and invitations (phase 5, ADR 0005) ----

    /// Create an organization: a new root key, whose public key is the org ID
    /// (returned, hex), its MLS group with this device as the only member, and a
    /// root-signed admin certificate for this device. The root key is kept in the
    /// store; only this device can make other admins ([`Self::grant_admin`]).
    pub fn create_org(&mut self) -> Result<String, ClientError> {
        self.create_org_with_root_key(&DeviceKey::generate().secret_bytes())
    }

    /// [`Self::create_org`] with a given root key secret, for apps that keep the
    /// root key elsewhere (e.g. a recovery backup). Fails if the org exists here.
    pub fn create_org_with_root_key(
        &mut self,
        root_secret: &[u8; 32],
    ) -> Result<String, ClientError> {
        let root = DeviceKey::from_secret_bytes(root_secret);
        let org_id = root.device_id();
        let org = org_id.to_hex();
        self.groups.create_group(&self.key, &org)?;
        let cert = MembershipCert::issue(&root, org_id, self.device_id(), true, now_ms());
        self.orgs.0.insert(
            org.clone(),
            org::OrgState {
                chain: Some(CertChain(vec![cert])),
                root: Some(*root_secret),
                invites: vec![],
            },
        );
        self.save_groups()?;
        self.save_orgs()?;
        // The policy object starts with our root-signed admin certificate, in a
        // change signed by the root key itself (no other admin can make one).
        let genesis = PolicyOp::Genesis {
            admin: MembershipCert::issue(&root, org_id, self.device_id(), true, now_ms()),
        };
        self.policy_commit_by(&org, genesis, Some(&root))?;
        Ok(org)
    }

    /// This device's membership proof for `org` (hex), empty if it has none yet.
    pub fn membership_proof(&self, org: &str) -> String {
        self.chain(org).map(CertChain::to_hex).unwrap_or_default()
    }

    /// True if this device may invite and admit devices to `org`.
    pub fn is_admin(&self, org: &str) -> bool {
        self.chain(org)
            .and_then(CertChain::leaf)
            .is_some_and(|c| c.admin)
    }

    fn chain(&self, org: &str) -> Option<&CertChain> {
        self.orgs.0.get(org).and_then(|s| s.chain.as_ref())
    }

    /// Frame announcing `org` to the relay with this device's membership proof.
    /// Without a proof (joining) the relay treats the device as pending.
    pub fn announce_frame(&self, org: &str) -> Frame {
        Frame::Announce {
            orgs: vec![kith_protocol::Membership {
                org: org.into(),
                proof: self.membership_proof(org),
                always_on: self.always_on,
                revoked: self
                    .revocations
                    .iter()
                    .filter(|r| r.org.to_hex() == org)
                    .map(Revocation::to_hex)
                    .collect(),
            }],
        }
    }

    /// Announce this device as an always-on client (a headless member that stays
    /// online): the relay then prefers it as catch-up partner (REQ-SYNC-006).
    pub fn set_always_on(&mut self, on: bool) {
        self.always_on = on;
    }

    /// The frames to send in answer to a relay's `challenge`: the signature that
    /// proves device ownership, then the announcement of `org`. `None` for any
    /// other frame.
    pub fn handshake_reply(&self, org: &str, frame: &Frame) -> Option<Vec<Frame>> {
        match frame {
            // Pipelined: a failed auth makes the relay send an error and close.
            Frame::Challenge { nonce } => {
                Some(vec![auth_frame(&self.key, nonce), self.announce_frame(org)])
            }
            _ => None,
        }
    }

    /// A one-time invite to `org`, valid for `ttl_ms` (REQ-INV-001). Returns the
    /// link to share (QR code, message). Only admins can invite; only this device
    /// can admit the claimer, so keep it online until then.
    pub fn create_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
    ) -> Result<String, ClientError> {
        if !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        self.issue_invite(org, relay, ttl_ms, 1)
    }

    /// A link that admits up to `max_uses` devices (REQ-INV-005, 1 to
    /// [`kith_core::membership::MAX_INVITE_USES`]), for example one link in a group
    /// chat. Everyone with the link can claim it, so the admin still sees each
    /// claim ([`Event::InviteClaimed`]) and decides with [`Self::accept_claim`] or
    /// [`Self::reject_claim`]; every admission uses one of the `max_uses`. The
    /// invite ends at its expiry or when the last use is taken. Admins only; this
    /// device must be online to admit.
    pub fn create_multi_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
        max_uses: u32,
    ) -> Result<String, ClientError> {
        if !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        if !(1..=kith_core::membership::MAX_INVITE_USES).contains(&max_uses) {
            return Err(ClientError::InvalidInvite(format!(
                "uses must be 1 to {}",
                kith_core::membership::MAX_INVITE_USES
            )));
        }
        self.issue_invite(org, relay, ttl_ms, max_uses)
    }

    fn issue_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
        uses: u32,
    ) -> Result<String, ClientError> {
        let org_id = DeviceId::from_hex(org)?;
        let invite = Invite::new_multi_use(org_id, relay, now_ms().saturating_add(ttl_ms), uses);
        let link = invite.to_link();
        self.orgs
            .0
            .entry(org.into())
            .or_default()
            .invites
            .push(invite);
        self.save_orgs()?;
        Ok(link)
    }

    /// A one-time link to add another device of *this user* to `org` (REQ-ID-002,
    /// ADR 0011). Any member can make one, not only admins. The new device gets this
    /// device's role (at most editor) and a certificate signed by this device; keep
    /// this device online until it is accepted ([`Self::accept_claim`]). Not
    /// available on a device that was itself added this way.
    pub fn create_own_device_invite(
        &mut self,
        org: &str,
        relay: &str,
        ttl_ms: u64,
    ) -> Result<String, ClientError> {
        let linkable = self
            .chain(org)
            .is_some_and(|c| c.leaf().is_some_and(|l| !l.own))
            && self.role_of(org, &self.device_id().to_hex())?.is_some();
        if !linkable {
            return Err(ClientError::Forbidden(
                "only a member that was not itself linked can add its own devices".into(),
            ));
        }
        let org_id = DeviceId::from_hex(org)?;
        let invite = Invite::new_own_device(
            org_id,
            relay,
            now_ms().saturating_add(ttl_ms),
            self.device_id(),
        );
        let link = invite.to_link();
        self.orgs
            .0
            .entry(org.into())
            .or_default()
            .invites
            .push(invite);
        self.save_orgs()?;
        Ok(link)
    }

    /// Claim an invite link (on the new device). Connect to `Claim::relay` and
    /// announce `Claim::org` (the client has no proof yet, so it is pending), then
    /// send `Claim::frame`. The admin answers with [`Event::ClaimCode`] (show the
    /// code); [`Event::Joined`] follows once it accepts.
    pub fn claim_invite(&mut self, link: &str) -> Result<Claim, ClientError> {
        let invite = Invite::parse(link).map_err(|e| ClientError::InvalidInvite(e.to_string()))?;
        if invite.is_expired(now_ms()) {
            return Err(ClientError::InvalidInvite("expired".into()));
        }
        let key_package = self.groups.key_package(&self.key)?;
        // The KeyPackage's private part must be stored before it leaves.
        self.save_groups()?;
        let org = invite.org.to_hex();
        self.joining.insert(org.clone(), invite.own_device);
        let body = sync::outer_body(&Outer::Claim {
            token: invite.token,
            proof: invite.claim_proof(&key_package),
            key_package: key_package.clone(),
        });
        self.claiming
            .insert(org.clone(), (invite.clone(), key_package));
        Ok(Claim {
            frame: Frame::InviteClaim {
                org: org.clone(),
                token: hex_encode(&invite.token),
                body,
                to: invite.own_device.map(|d| d.to_hex()),
            },
            relay: invite.relay,
            org,
        })
    }

    /// Admit the device of an [`Event::InviteClaimed`]: adds it to the MLS group,
    /// issues its membership certificate and uses up the invite. Send the frames
    /// (in order: the policy change naming the device, the commit to the group, the
    /// Welcome to the device).
    pub fn accept_claim(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        let (kp, token, _) = self
            .claims
            .remove(&(org.to_string(), device.to_string()))
            .ok_or_else(|| {
                ClientError::InvalidInvite("no pending claim from that device".into())
            })?;
        // One invite admits one device, and only until it expires: the claim was
        // checked when it arrived, but the invite may have been used or expired since.
        let invite = self
            .orgs
            .0
            .get(org)
            .and_then(|s| s.invites.iter().find(|i| i.token == token))
            .cloned()
            .ok_or_else(|| ClientError::InvalidInvite("invite already used".into()))?;
        if invite.is_expired(now_ms()) {
            return Err(ClientError::InvalidInvite("invite expired".into()));
        }
        let own = invite.own_device == Some(self.device_id());
        if !own && !self.is_admin(org) {
            return Err(ClientError::NotAdmin(org.into()));
        }
        if own
            && !self
                .chain(org)
                .is_some_and(|c| c.leaf().is_some_and(|l| !l.own))
        {
            return Err(ClientError::Forbidden(
                "a linked device cannot add devices".into(),
            ));
        }
        // The policy learns that the new device is ours (refused, with nothing
        // changed, if the device already has a role or link), or, for an admin's
        // admission, names it as an editor: devices the policy does not name have
        // no role. Refused if a more senior admin revoked the device.
        let d = DeviceId::from_hex(device)?;
        let link = if own {
            Some(self.policy_commit(org, PolicyOp::LinkDevice { device: d })?)
        } else if self
            .policies
            .get(org)
            .is_some_and(|p| p.creator.is_some() && p.role_of(&d).is_none())
        {
            let op = PolicyOp::SetRole {
                device: d,
                role: Role::Editor,
                cert: None,
            };
            Some(self.policy_commit(org, op)?)
        } else {
            None
        };
        if self.groups.key_package_device(&kp)?.to_hex() != device {
            return Err(ClientError::InvalidInvite(
                "KeyPackage of another device".into(),
            ));
        }
        // The policy change goes out first, in the current epoch: members check the
        // commit that adds the device against it.
        let policy_frame = match &link {
            Some(change) => Some(self.broadcast_frame(org, change)?),
            None => None,
        };
        let added = self.groups.add_member(&self.key, org, &kp)?;
        self.save_groups()?;
        // An admin's chain is its root-issued admin certificate, which vouches for
        // the one we issue now: root -> us -> new device.
        let org_id = DeviceId::from_hex(org)?;
        let mut chain = self.chain(org).cloned().map(|c| c.0).unwrap_or_default();
        chain.push(if own {
            MembershipCert::issue_own(&self.key, org_id, added.member, now_ms())
        } else {
            MembershipCert::issue(&self.key, org_id, added.member, false, now_ms())
        });
        // One use is taken; the invite ends with its last one (REQ-INV-005).
        let mut used_up = true;
        if let Some(st) = self.orgs.0.get_mut(org) {
            for i in st.invites.iter_mut().filter(|i| i.token == token) {
                i.uses = i.uses.saturating_sub(1);
                used_up = i.uses == 0;
            }
            st.invites.retain(|i| i.uses > 0);
        }
        // Other devices' claims on a used-up invite can't be admitted any more.
        if used_up {
            self.claims.retain(|_, (_, t, _)| *t != token);
        }
        self.save_orgs()?;
        let mut frames: Vec<Frame> = policy_frame.into_iter().collect();
        frames.push(Frame::Broadcast {
            org: org.into(),
            body: sync::outer_body(&Outer::Commit(added.commit)),
        });
        frames.push(direct(
            org,
            device,
            sync::outer_body(&Outer::Welcome {
                welcome: added.welcome,
                chain: CertChain(chain).to_hex(),
            }),
        ));
        Ok(frames)
    }

    /// Refuse a pending claim (for example: the short codes did not match). The
    /// invite stays valid until it is used or expires.
    pub fn reject_claim(&mut self, org: &str, device: &str) {
        self.claims.remove(&(org.to_string(), device.to_string()));
    }

    /// Make `device` (hex, a member) an admin of `org`: a root-signed certificate
    /// for the relay and an admin role in the policy. Only the device holding the
    /// org root key can. Send the returned frames; the device re-announces itself.
    pub fn grant_admin(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        let cert = self.root_admin_cert(org, DeviceId::from_hex(device)?)?;
        let change = self.set_role(org, device, Role::Admin)?;
        Ok(vec![
            direct(
                org,
                device,
                sync::outer_body(&Outer::Cert(CertChain(vec![cert]).to_hex())),
            ),
            self.broadcast_frame(org, &change)?,
        ])
    }

    fn save_orgs(&mut self) -> Result<(), ClientError> {
        let sealed = sealed::seal(
            &self.storage_key,
            ORGS_KEY,
            &zeroize::Zeroizing::new(self.orgs.to_bytes()),
        );
        Ok(self.store.put_meta(ORGS_KEY, &sealed)?)
    }

    /// True if `chain` (as sent in an `Outer::Cert`) may replace our proof for
    /// `org`: it makes us an admin where we were not, or its certificate is newer
    /// than ours. A replayed older certificate can't take admin rights away.
    fn is_newer_chain(&self, org: &str, chain: &str) -> bool {
        let Some(current) = self.chain(org).and_then(|c| c.leaf()) else {
            return true;
        };
        let Some(new) = CertChain::from_hex(chain)
            .ok()
            .and_then(|c| c.leaf().cloned())
        else {
            return true; // adopt_chain reports why it is invalid
        };
        (new.admin && !current.admin) || new.issued_ms > current.issued_ms
    }

    /// Store `chain` as our proof for `org` if it proves exactly that.
    fn adopt_chain(&mut self, org: &str, chain: &str) -> Result<bool, String> {
        let org_id = DeviceId::from_hex(org).map_err(|e| e.to_string())?;
        let chain = CertChain::from_hex(chain).map_err(|e| e.to_string())?;
        let proven = chain
            .verify(&org_id, &self.device_id())
            .map_err(|e| e.to_string())?;
        self.orgs.0.entry(org.into()).or_default().chain = Some(chain);
        Ok(proven.admin)
    }

    // ---- MLS group (REQ-ENC-001..004) ----

    /// True if this device is a member of `org`'s group (it can send and read).
    pub fn is_member(&self, org: &str) -> bool {
        self.groups.is_member(org)
    }

    /// Current epoch of `org`'s group.
    pub fn group_epoch(&self, org: &str) -> Result<u64, ClientError> {
        Ok(self.groups.epoch(org)?)
    }

    /// Devices (hex) in `org`'s group.
    pub fn group_members(&self, org: &str) -> Result<Vec<String>, ClientError> {
        Ok(self
            .groups
            .members(org)?
            .iter()
            .map(DeviceId::to_hex)
            .collect())
    }

    /// A certified member without MLS state for `org` (restored from a backup) asks
    /// an online peer to re-add it, once.
    fn rejoin_if_needed(
        &mut self,
        org: &str,
        online: &[String],
    ) -> Result<Vec<Frame>, ClientError> {
        let me = self.device_id().to_hex();
        if self.groups.has_group(org)
            || self.chain(org).is_none()
            || self.rejoin_asked.contains(org)
        {
            return Ok(vec![]);
        }
        let Some(peer) = online.iter().find(|d| **d != me) else {
            return Ok(vec![]);
        };
        self.rejoin_asked.insert(org.into());
        Ok(vec![self.readd_request_frame(org, org, peer)?])
    }

    /// Ask the member `to` to re-add this device (after a fork or falling too far
    /// behind, REQ-ENC-004): sends a fresh KeyPackage.
    fn readd_request_frame(
        &mut self,
        org: &str,
        group: &str,
        to: &str,
    ) -> Result<Frame, ClientError> {
        let peer = DeviceId::from_hex(to)?;
        let key_package = self.groups.key_package(&self.key)?;
        // The private part must be stored before the KeyPackage leaves.
        self.save_groups()?;
        self.welcome_from.insert(group.into(), peer);
        Ok(direct(
            org,
            to,
            sync::outer_body(&Outer::KeyPackage {
                group: group.into(),
                key_package,
            }),
        ))
    }

    fn readded_frames(&self, org: &str, added: kith_crypto::Added) -> Vec<Frame> {
        vec![
            Frame::Broadcast {
                org: org.into(),
                body: sync::outer_body(&Outer::Commit(added.commit)),
            },
            direct(
                org,
                &added.member.to_hex(),
                // A re-added device keeps its certificate.
                sync::outer_body(&Outer::Welcome {
                    welcome: added.welcome,
                    chain: String::new(),
                }),
            ),
        ]
    }

    /// Remove `device` (hex) from `org` (REQ-INV-004): out of the MLS group, so it
    /// cannot read anything sent afterwards, and revoked in the policy, so its
    /// changes this device has not seen are rejected everywhere. Admins only. Send
    /// the returned frames in order.
    pub fn remove_member(&mut self, org: &str, device: &str) -> Result<Vec<Frame>, ClientError> {
        // The user's other devices (ADR 0011) go with it: revoked by the policy
        // through the link, removed from the group here.
        let primary = DeviceId::from_hex(device)?;
        let members = self.groups.members(org)?;
        let linked: Vec<DeviceId> = self
            .policies
            .get(org)
            .map_or(vec![], |p| p.linked_to(&primary))
            .into_iter()
            .filter(|d| members.contains(d))
            .collect();
        let revocation = self.revoke(org, device)?;
        // The relay hears of it too (REQ-INV-004): a signed notice, repeated on
        // every announce, so it refuses the device and the ones it certified.
        // Signed by the root key when we hold it: only that removes an admin at the
        // relay, and it stays valid whatever happens to our own admin rights.
        let root = self.orgs.0.get(org).and_then(|s| s.root);
        let notice = match root {
            Some(root) => {
                Revocation::issue_by_root(&DeviceKey::from_secret_bytes(&root), primary, now_ms())
            }
            None => Revocation::issue(
                &self.key,
                self.chain(org)
                    .cloned()
                    .ok_or_else(|| ClientError::NotAdmin(org.into()))?,
                DeviceId::from_hex(org)?,
                primary,
                now_ms(),
            ),
        };
        self.revocations.push(notice);
        self.save_revocations()?;
        let mut frames = vec![];
        let mut gone = vec![primary];
        gone.extend(linked);
        for d in gone {
            let commit = self.groups.remove_member(&self.key, org, d)?;
            self.save_groups()?;
            frames.push(Frame::Broadcast {
                org: org.into(),
                body: sync::outer_body(&Outer::Commit(commit)),
            });
        }
        frames.push(self.broadcast_frame(org, &revocation)?);
        // The other admins and the always-on client keep the notice too, so one of
        // them can repeat it if this device is gone (ADR 0024).
        let shared = vec![self.revocations[self.revocations.len() - 1].to_hex()];
        for body in sync::notices_bodies(&shared) {
            let body = self.app_body(org, &body)?;
            self.save_groups()?;
            frames.push(Frame::Broadcast {
                org: org.into(),
                body,
            });
        }
        frames.push(self.announce_frame(org));
        Ok(frames)
    }

    /// Number of revocation notices this device repeats to the relay for `org`.
    pub fn held_revocations(&self, org: &str) -> usize {
        self.revocations
            .iter()
            .filter(|r| r.org.to_hex() == org)
            .count()
    }

    /// Keep notices that other members shared (ADR 0024). Only admins and the
    /// always-on client keep them: they are the ones that repeat notices on announce.
    /// Each must verify for `org` on its own, so a member cannot plant anything.
    fn learn_notices(&mut self, org: &str, lines: &[String]) -> Result<(), ClientError> {
        if !(self.always_on || self.is_admin(org)) || self.chain(org).is_none() {
            return Ok(());
        }
        let Ok(org_id) = DeviceId::from_hex(org) else {
            return Ok(());
        };
        let mut changed = false;
        for line in lines {
            let Ok(notice) = Revocation::from_hex(line) else {
                continue;
            };
            if notice.verify(&org_id).is_err()
                || self.held_revocations(org) >= MAX_HELD_NOTICES
                || self.revocations.iter().any(|r| r == &notice)
            {
                continue;
            }
            self.revocations.push(notice);
            changed = true;
        }
        if changed {
            self.save_revocations()?;
        }
        Ok(())
    }

    fn save_revocations(&mut self) -> Result<(), ClientError> {
        let text: String = self.revocations.iter().map(|r| r.to_hex() + "\n").collect();
        Ok(self.store.put_meta(REVOCATIONS_KEY, text.as_bytes())?)
    }

    /// Rotate this device's key in `org`'s group (MLS update, REQ-ENC-003): call
    /// it periodically, e.g. weekly or on start after a long pause. Send the
    /// returned commit.
    pub fn rotate_key(&mut self, org: &str) -> Result<Frame, ClientError> {
        let commit = self.groups.self_update(&self.key, org)?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body: sync::outer_body(&Outer::Commit(commit)),
        })
    }

    // ---- data sync ----

    /// Frame that broadcasts a new change, encrypted for `org`'s group, to the
    /// other online devices (REQ-SYNC-004).
    pub fn broadcast_frame(&mut self, org: &str, change: &Change) -> Result<Frame, ClientError> {
        if !in_org(org, change.body.scope.as_str()) {
            return Err(ClientError::Forbidden(format!(
                "change belongs to scope {}, not org {org}",
                change.body.scope
            )));
        }
        // Encrypted for the scope's group: subgroup data only its members can read.
        let body = self.app_body(change.body.scope.as_str(), &sync::change_body(change))?;
        self.save_groups()?;
        Ok(Frame::Broadcast {
            org: org.into(),
            body,
        })
    }

    /// The request that starts catch-up (REQ-SYNC-001..003): send it to the relay,
    /// which hands it to one online peer. The two reconcile their sets of changes
    /// in a few rounds (traffic grows with the difference, not the history), then
    /// each sends what the other lacks: [`Event::SyncCompared`], then
    /// [`Event::SyncReceived`]. Works from an empty store (join). The relay's
    /// `Receipt` shows whether a peer was online (`delivered` empty: try later).
    pub fn sync_request_frame(&mut self, org: &str) -> Result<Frame, ClientError> {
        let body = self.start_reconcile(org, None)?;
        self.save_groups()?;
        Ok(Frame::SyncRequest {
            org: org.into(),
            body,
        })
    }

    /// Start (or restart) our reconciliation for `scope` (an org or `org/subgroup`
    /// key); returns the first query, encrypted for that scope's group.
    /// `peer`: the device the query goes to (`Direct`), or `None` for a
    /// `SyncRequest` (the relay picks one).
    fn start_reconcile(&mut self, scope: &str, peer: Option<&str>) -> Result<Vec<u8>, ClientError> {
        let ids = self.store.scope_ids(&org_scope(scope)?)?;
        let (r, first) = kith_sync::Reconciliation::start(&ids)?;
        let body = self.app_body(scope, &sync::query_body(&first))?;
        self.reconciling
            .insert(scope.into(), (r, peer.map(str::to_string)));
        Ok(body)
    }

    /// Catch-up requests for `org` and for each of its subgroups this device is in
    /// (those go `direct` to a subgroup member: the relay does not know them), plus
    /// any pending subgroup membership messages.
    pub fn sync_request_frames(&mut self, org: &str) -> Result<Vec<Frame>, ClientError> {
        let mut frames = vec![self.sync_request_frame(org)?];
        let me = self.device_id();
        let subs: Vec<String> = self
            .groups
            .orgs()
            .into_iter()
            .filter(|g| in_org(org, g) && g.as_str() != org && self.groups.is_member(g))
            .collect();
        for g in subs {
            let owner = self.subgroup_owner(org, &g);
            let peer = owner
                .filter(|o| *o != me)
                .or_else(|| self.groups.members(&g).ok()?.into_iter().find(|d| *d != me));
            if let Some(peer) = peer {
                let peer = peer.to_hex();
                let body = self.start_reconcile(&g, Some(&peer))?;
                frames.push(direct(org, &peer, body));
            }
        }
        self.kp_asked.retain(|g| !in_org(org, g));
        frames.extend(self.subgroup_tasks()?);
        self.save_groups()?;
        Ok(frames)
    }

    fn subgroup_owner(&self, org: &str, group: &str) -> Option<DeviceId> {
        let name = group.strip_prefix(org)?.strip_prefix('/')?;
        self.policies.get(org)?.subgroup_owners.get(name).copied()
    }

    /// Bring MLS subgroups in line with the policy (6b-2): the owner creates the
    /// group and removes devices the policy no longer lists; a listed member that is
    /// not in the group yet sends the owner a KeyPackage.
    fn subgroup_tasks(&mut self) -> Result<Vec<Frame>, ClientError> {
        let me = self.device_id();
        let mut frames = vec![];
        let mut wanted: Vec<(
            String,
            String,
            std::collections::BTreeSet<DeviceId>,
            DeviceId,
        )> = vec![];
        for (org, policy) in &self.policies {
            for (name, members) in &policy.subgroups {
                if let Some(owner) = policy.subgroup_owners.get(name) {
                    wanted.push((
                        org.clone(),
                        format!("{org}/{name}"),
                        members.clone(),
                        *owner,
                    ));
                }
            }
        }
        for (org, key, members, owner) in wanted {
            if owner == me {
                if !self.groups.has_group(&key) {
                    self.groups.create_group(&self.key, &key)?;
                }
                let stale: Vec<DeviceId> = self
                    .groups
                    .members(&key)?
                    .into_iter()
                    .filter(|d| *d != me && !members.contains(d))
                    .collect();
                for d in stale {
                    let commit = self.groups.remove_member(&self.key, &key, d)?;
                    frames.push(Frame::Broadcast {
                        org: org.clone(),
                        body: sync::outer_body(&Outer::Commit(commit)),
                    });
                }
            } else if members.contains(&me)
                && !self.groups.is_member(&key)
                && self.kp_asked.insert(key.clone())
            {
                frames.push(self.readd_request_frame(&org, &key, &owner.to_hex())?);
            }
        }
        if !frames.is_empty() {
            self.save_groups()?;
        }
        Ok(frames)
    }

    /// The owner's side of a member's KeyPackage for subgroup `group` (`org/name`).
    fn subgroup_key_package(
        &mut self,
        org: String,
        group: String,
        from: String,
        key_package: &[u8],
    ) -> Result<Handled, ClientError> {
        let rejected = |reason: &str| {
            Ok(Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason: reason.into(),
            }))
        };
        let me = self.device_id();
        let Some(name) = group.strip_prefix(&org).and_then(|g| g.strip_prefix('/')) else {
            return rejected("not a subgroup of this org");
        };
        let Some(policy) = self.policies.get(&org) else {
            return rejected("no policy");
        };
        if policy.subgroup_owners.get(name) != Some(&me) {
            return Ok(Handled::event(Event::Ignored));
        }
        let listed = DeviceId::from_hex(&from)
            .ok()
            .is_some_and(|d| policy.subgroup(name).is_some_and(|m| m.contains(&d)));
        if !listed {
            return rejected("not a member of this subgroup in the policy");
        }
        if !self
            .groups
            .key_package_device(key_package)
            .is_ok_and(|d| d.to_hex() == from)
        {
            return rejected("KeyPackage is not the sender's");
        }
        let already = self
            .groups
            .members(&group)
            .is_ok_and(|m| m.iter().any(|d| d.to_hex() == from));
        let added = if already {
            self.groups.readd_member(&self.key, &group, key_package)
        } else {
            self.groups.add_member(&self.key, &group, key_package)
        };
        let added = match added {
            Ok(a) if a.member.to_hex() == from => a,
            Ok(_) => return rejected("KeyPackage is not the sender's"),
            Err(e) => return rejected(&e.to_string()),
        };
        self.save_groups()?;
        Ok(Handled {
            replies: self.readded_frames(&org, added),
            event: if already {
                Event::MemberReAdded {
                    org: group,
                    device: from,
                }
            } else {
                Event::MemberAdded {
                    org: group,
                    device: from,
                }
            },
        })
    }

    /// Encrypt an inner message as an outer `App` body. The caller saves the
    /// MLS state before the body leaves the device.
    fn app_body(&mut self, org: &str, inner: &[u8]) -> Result<Vec<u8>, ClientError> {
        let ct = self.groups.encrypt(&self.key, org, inner)?;
        Ok(sync::outer_body(&Outer::App(ct)))
    }

    fn save_groups(&mut self) -> Result<(), ClientError> {
        let sealed = sealed::seal(&self.storage_key, MLS_STATE_KEY, &self.groups.to_bytes());
        Ok(self.store.put_meta(MLS_STATE_KEY, &sealed)?)
    }

    /// Handle a frame from the relay: decrypt it, validate and store peers'
    /// changes (REQ-SYNC-004), serve catch-up requests and absorb offers
    /// (REQ-SYNC-001..003), apply MLS commits and Welcomes and catch up on missed
    /// commits (REQ-ENC-001..004). Send `Handled::replies` to the relay.
    ///
    /// A bad message from a peer is reported as [`Event::Rejected`], not as an
    /// error, so a misbehaving device cannot break the receive loop. Only local
    /// failures (storage, MLS state) return `Err`.
    pub fn handle_frame(&mut self, frame: Frame) -> Result<Handled, ClientError> {
        let handled = match frame {
            Frame::Deliver { org, from, body } => {
                let mut h = self.handle_deliver(org, from, &body, false)?;
                h.replies.extend(self.subgroup_tasks()?);
                h
            }
            Frame::ClaimDeliver { org, from, body } => {
                self.handle_deliver(org, from, &body, true)?
            }
            Frame::Presence { org, online } => {
                let replies = self.rejoin_if_needed(&org, &online)?;
                Handled {
                    replies,
                    event: Event::Presence { org, online },
                }
            }
            Frame::Receipt { delivered } => Handled::event(Event::Receipt { delivered }),
            Frame::Error { code, message } => Handled::event(Event::RelayError { code, message }),
            _ => return Ok(Handled::event(Event::Ignored)),
        };
        // Decrypting advances ratchets and replies are encrypted: save before any
        // reply is sent.
        self.save_groups()?;
        Ok(handled)
    }

    /// `claim`: it came as a [`Frame::ClaimDeliver`], from a device that may not be
    /// a member. Only claims are taken from it, and claims only from it.
    fn handle_deliver(
        &mut self,
        org: String,
        from: String,
        body: &[u8],
        claim: bool,
    ) -> Result<Handled, ClientError> {
        let rejected = |reason: String| {
            Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            })
        };
        let outer = match sync::parse_outer(body) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        if claim != matches!(outer, Outer::Claim { .. }) {
            return Ok(rejected(if claim {
                "only an invite claim can come from a claiming device".into()
            } else {
                "an invite claim must come as a claim".into()
            }));
        }
        match outer {
            Outer::App(ct) => {
                let Some(group) = self.group_in(&org, &ct) else {
                    return Ok(rejected("message for another org".into()));
                };
                if group == SUBGROUP_NOT_OURS {
                    // Subgroup traffic we are not part of: reaches all of the org.
                    return Ok(Handled::event(Event::Ignored));
                }
                self.handle_app(org, group, from, &ct)
            }
            Outer::Commit(commit) => {
                let Some(group) = self.group_in(&org, &commit) else {
                    return Ok(rejected("commit for another org".into()));
                };
                if group == SUBGROUP_NOT_OURS {
                    return Ok(Handled::event(Event::Ignored));
                }
                // A broadcast commit comes from its committer.
                let Ok(committer) = DeviceId::from_hex(&from) else {
                    return Ok(rejected("sender is not a device ID".into()));
                };
                let check = self.commit_check(&org, &group);
                match self
                    .groups
                    .apply_commit_checked(&group, &commit, committer, check)
                {
                    Ok(CommitOutcome::Applied { epoch, removed }) => {
                        Ok(Handled::event(Event::GroupChanged {
                            org: group,
                            epoch,
                            removed,
                        }))
                    }
                    Ok(CommitOutcome::Stale) => Ok(Handled::event(Event::Ignored)),
                    // A fork we cannot verify (the epoch is gone): only a member we
                    // trust makes us ask to be re-added.
                    Ok(CommitOutcome::Fork { .. }) if !self.trusted_member(&org, &group, &from) => {
                        Ok(rejected("fork claimed by a non-member".into()))
                    }
                    Ok(CommitOutcome::Fork { we_win, .. }) => {
                        self.on_fork(org, group, from, we_win)
                    }
                    Err(GroupError::EpochGap { local, .. }) => {
                        Ok(self.behind(org, group, from, local))
                    }
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::Welcome { welcome, chain } => {
                let check = self.welcome_check(&org, &from, &chain);
                let joined = match self.groups.join_checked(&welcome, check) {
                    Ok(o) => o,
                    Err(e) => return Ok(rejected(e.to_string())),
                };
                self.welcome_from.remove(&joined);
                if joined == org {
                    self.joining.remove(&org);
                    self.claiming.remove(&org);
                }
                self.readd_asked.remove(&joined);
                if joined.contains('/') {
                    // A subgroup: fetch its history from the owner that added us.
                    self.kp_asked.remove(&joined);
                    let body = self.start_reconcile(&joined, Some(&from))?;
                    return Ok(Handled {
                        event: Event::Joined {
                            org: joined.clone(),
                        },
                        replies: vec![direct(&org, &from, body)],
                    });
                }
                if !chain.is_empty() {
                    if let Err(e) = self.adopt_chain(&joined, &chain) {
                        return Ok(rejected(format!("membership certificate: {e}")));
                    }
                    self.save_orgs()?;
                }
                // Announce with the certificate (we were pending), then ask a peer
                // for the history.
                let body = self.start_reconcile(&joined, None)?;
                Ok(Handled {
                    event: Event::Joined {
                        org: joined.clone(),
                    },
                    replies: vec![
                        self.announce_frame(&joined),
                        Frame::SyncRequest { org: joined, body },
                    ],
                })
            }
            Outer::Claim {
                token,
                proof,
                key_package,
            } => {
                let Some(invite) = self
                    .orgs
                    .0
                    .get(&org)
                    .and_then(|s| s.invites.iter().find(|i| i.token == token))
                    .cloned()
                else {
                    // Every admin of the org gets the claim; only the issuer knows it.
                    return Ok(Handled::event(Event::Ignored));
                };
                if invite.is_expired(now_ms()) {
                    return Ok(rejected("invite expired".into()));
                }
                if !invite.verify_claim(&key_package, &proof) {
                    return Ok(rejected("invite proof does not match".into()));
                }
                match self.groups.key_package_device(&key_package) {
                    Ok(d) if d.to_hex() == from => {}
                    _ => return Ok(rejected("KeyPackage is not the sender's".into())),
                }
                let key = (org.clone(), from.clone());
                let pending = self.claims.values().filter(|c| c.1 == token).count();
                if !self.claims.contains_key(&key) && pending >= MAX_CLAIMS_PER_INVITE {
                    return Ok(rejected("too many claims for this invite".into()));
                }
                // A repeated claim with the same KeyPackage keeps its nonce (and code).
                let nonce = match self.claims.get(&key) {
                    Some((kp, t, n)) if *kp == key_package && *t == token => *n,
                    _ => kith_core::random_bytes(),
                };
                let code = invite.short_code(&key_package, &nonce);
                let answer = sync::outer_body(&Outer::ClaimNonce {
                    token,
                    nonce,
                    signature: self
                        .key
                        .sign(&invite.nonce_signed_bytes(&key_package, &nonce)),
                    chain: self.chain(&org).map(CertChain::to_hex).unwrap_or_default(),
                });
                self.claims.insert(key, (key_package, token, nonce));
                Ok(Handled {
                    replies: vec![direct(&org, &from, answer)],
                    event: Event::InviteClaimed { org, from, code },
                })
            }
            Outer::ClaimNonce {
                token,
                nonce,
                signature,
                chain,
            } => Ok(
                match self.claim_code(&org, &from, token, &nonce, &signature, &chain) {
                    Ok(code) => Handled::event(Event::ClaimCode { org, from, code }),
                    Err(e) => rejected(e),
                },
            ),
            Outer::Cert(chain) if !self.is_newer_chain(&org, &chain) => {
                Ok(rejected("membership certificate: older than ours".into()))
            }
            Outer::Cert(chain) => match self.adopt_chain(&org, &chain) {
                Ok(admin) => {
                    self.save_orgs()?;
                    Ok(Handled {
                        replies: vec![self.announce_frame(&org)],
                        event: Event::CertificateUpdated { org, admin },
                    })
                }
                Err(e) => Ok(rejected(format!("membership certificate: {e}"))),
            },
            Outer::KeyPackage { group, key_package } if group != org => {
                if !in_org(&org, &group) {
                    return Ok(rejected("group of another org".into()));
                }
                self.subgroup_key_package(org, group, from, &key_package)
            }
            Outer::KeyPackage {
                key_package: kp, ..
            } => {
                if !self.trusted_member(&org, &org, &from) {
                    return Ok(rejected("not a member: join with an invite".into()));
                }
                // A member that lost the group (REQ-ENC-004). Only for its own key,
                // checked before the group changes.
                if !self
                    .groups
                    .key_package_device(&kp)
                    .is_ok_and(|d| d.to_hex() == from)
                {
                    return Ok(rejected("KeyPackage is not the sender's".into()));
                }
                match self.groups.readd_member(&self.key, &org, &kp) {
                    Ok(added) => Ok(Handled {
                        replies: self.readded_frames(&org, added),
                        event: Event::MemberReAdded { org, device: from },
                    }),
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Outer::CommitRequest { group, .. }
            | Outer::Commits { group, .. }
            | Outer::ReaddNeeded { group }
                if !in_org(&org, &group) =>
            {
                Ok(rejected("group of another org".into()))
            }
            Outer::CommitRequest { group, epoch } => {
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                Ok(self.serve_commits(org, group, from, epoch)?)
            }
            Outer::Commits { group, commits } => {
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                let mut applied = 0;
                for (committer, c) in &commits {
                    let check = self.commit_check(&org, &group);
                    match self
                        .groups
                        .apply_commit_checked(&group, c, *committer, check)
                    {
                        Ok(CommitOutcome::Applied { .. }) => applied += 1,
                        Ok(CommitOutcome::Stale) => {}
                        // The rest of the batch belongs to the other branch.
                        Ok(CommitOutcome::Fork { we_win, .. }) => {
                            return self.on_fork(org, group, from, we_win);
                        }
                        Err(e) => return Ok(rejected(e.to_string())),
                    }
                }
                let epoch = self.groups.epoch(&group)?;
                // Data sent while we were behind could not be read: resync with this peer.
                let replies = if applied > 0 && self.groups.is_member(&group) {
                    vec![direct(
                        &org,
                        &from,
                        self.start_reconcile(&group, Some(&from))?,
                    )]
                } else {
                    vec![]
                };
                Ok(Handled {
                    event: Event::CommitsApplied {
                        org: group,
                        from,
                        applied,
                        epoch,
                    },
                    replies,
                })
            }
            Outer::ReaddNeeded { group } => {
                // Only a group we have can be re-joined, and only a member of it,
                // that the policy does not exclude, can tell us to.
                if self.groups.epoch(&group).is_err() {
                    return Ok(rejected("not in this group".into()));
                }
                if !self.trusted_member(&org, &group, &from) {
                    return Ok(rejected("not a member of this group".into()));
                }
                let frame = self.readd_request_frame(&org, &group, &from)?;
                Ok(Handled {
                    event: Event::ReAddRequested { org: group, from },
                    replies: vec![frame],
                })
            }
        }
    }

    /// Is `device` (hex) in our view of `group` and not excluded by `org`'s policy?
    fn trusted_member(&self, org: &str, group: &str, device: &str) -> bool {
        let Ok(d) = DeviceId::from_hex(device) else {
            return false;
        };
        self.groups.members(group).is_ok_and(|m| m.contains(&d))
            && self
                .policies
                .get(org)
                .filter(|p| p.creator.is_some())
                .is_none_or(|p| p.role_of(&d).is_some())
    }

    /// What a commit in `group` (of `org`) may change (ADR 0017). With a policy:
    /// in the org's group, admins add and remove devices, a member may add a device
    /// linked to it, and any member may re-add a device that is already in the
    /// group; revoked devices are never added. In a subgroup only its owner adds,
    /// re-adds and removes, and only listed devices are added. Key updates are
    /// always allowed. Without a policy everything is allowed.
    fn commit_check(
        &self,
        org: &str,
        group: &str,
    ) -> impl FnOnce(&kith_crypto::CommitInfo) -> Result<(), String> + use<S, K> {
        let policy = self
            .policies
            .get(org)
            .filter(|p| p.creator.is_some())
            .cloned();
        let subgroup = group
            .strip_prefix(org)
            .and_then(|g| g.strip_prefix('/'))
            .map(str::to_string);
        move |c| {
            let Some(p) = policy else {
                return Ok(());
            };
            let by = c.committer;
            let readded = |d: &DeviceId| c.added.contains(d) && c.removed.contains(d);
            if let Some(d) = c.added.iter().find(|d| p.revoked.contains(d)) {
                return Err(format!("{d} is revoked"));
            }
            match subgroup {
                None => {
                    let admin = p.role_of(&by) == Some(Role::Admin);
                    if p.role_of(&by).is_none() {
                        return Err(format!("{by} has no role"));
                    }
                    for d in &c.added {
                        if !(admin || readded(d) || p.links.get(d) == Some(&by)) {
                            return Err(format!("{by} may not add {d}"));
                        }
                    }
                    for d in &c.removed {
                        if !(admin || readded(d)) {
                            return Err(format!("{by} may not remove {d}"));
                        }
                    }
                }
                Some(name) => {
                    let changes = !c.added.is_empty() || !c.removed.is_empty();
                    if changes && p.subgroup_owners.get(&name) != Some(&by) {
                        return Err("only the subgroup's owner changes its members".into());
                    }
                    let listed = p.subgroup(&name);
                    if let Some(d) = c
                        .added
                        .iter()
                        .find(|d| !listed.is_some_and(|l| l.contains(d)))
                    {
                        return Err(format!("{d} is not in the subgroup"));
                    }
                }
            }
            Ok(())
        }
    }

    /// The checks a Welcome delivered in `org` by `from` must pass before we join
    /// (ADR 0016). We join only a group we asked to be added to, from the device we
    /// asked; or, the first time, the org's group from the device that issued our
    /// membership certificate (`chain`). Every device in the new group must be one
    /// we accept as a member.
    /// Check the admin's answer to our claim and derive the short code. The signer
    /// must be an admin of the org (or the issuing member of an own-device invite);
    /// from then on only its Welcome is accepted.
    fn claim_code(
        &mut self,
        org: &str,
        from: &str,
        token: [u8; 16],
        nonce: &[u8; 32],
        signature: &[u8; 64],
        chain: &str,
    ) -> Result<String, String> {
        let (invite, kp) = self
            .claiming
            .get(org)
            .filter(|(i, _)| i.token == token)
            .ok_or("no claim of ours for this invite")?;
        let signer = DeviceId::from_hex(from).map_err(|e| e.to_string())?;
        let proven = CertChain::from_hex(chain)
            .and_then(|c| c.verify(&invite.org, &signer))
            .map_err(|e| format!("answer to our claim: {e}"))?;
        let allowed = match invite.own_device {
            Some(issuer) => issuer == signer,
            None => proven.admin,
        };
        if !allowed {
            return Err("answer to our claim not from an admin or the invite's issuer".into());
        }
        kith_core::verify_signature(&signer, &invite.nonce_signed_bytes(kp, nonce), signature)
            .map_err(|_| "answer to our claim: bad signature".to_string())?;
        let code = invite.short_code(kp, nonce);
        self.joining.insert(org.into(), Some(signer));
        Ok(code)
    }

    fn welcome_check(
        &self,
        org: &str,
        from: &str,
        chain: &str,
    ) -> impl FnOnce(&kith_crypto::WelcomeInfo) -> Result<(), String> + use<S, K> {
        let org = org.to_string();
        let from = DeviceId::from_hex(from).ok();
        let me = self.device_id();
        let asked = self.welcome_from.clone();
        let first_join = !self.groups.has_group(&org) && self.chain(&org).is_none();
        let joining = self.joining.get(&org).copied();
        let policy = self
            .policies
            .get(&org)
            .filter(|p| p.creator.is_some())
            .cloned();
        let current = self.groups.members(&org).unwrap_or_default();
        let chain = chain.to_string();
        move |w| {
            let adder = w.adder.ok_or("Welcome without an adder")?;
            if Some(adder) != from {
                return Err("Welcome not signed by its sender".into());
            }
            if !in_org(&org, &w.group) {
                return Err("Welcome for a group of another org".into());
            }
            if asked.get(&w.group) == Some(&adder) {
                let Some(p) = policy else {
                    return Ok(());
                };
                if w.group == org {
                    // Members the policy names, or that our group already had.
                    if let Some(m) = w.members.iter().find(|m| {
                        p.role_of(m).is_none() && (p.revoked.contains(m) || !current.contains(m))
                    }) {
                        return Err(format!("{m} in the new group is not a member"));
                    }
                } else {
                    let name = &w.group[org.len() + 1..];
                    if p.subgroup_owners.get(name) != Some(&adder) {
                        return Err("Welcome not from the subgroup's owner".into());
                    }
                    let listed = p.subgroup(name);
                    if let Some(m) = w
                        .members
                        .iter()
                        .find(|m| !listed.is_some_and(|l| l.contains(m)))
                    {
                        return Err(format!("{m} is not in the subgroup"));
                    }
                }
                return Ok(());
            }
            if w.group == org && first_join && !w.replaces {
                // Our first join: the adder issued the certificate it sends us,
                // under the org root key.
                let org_id = DeviceId::from_hex(&org).map_err(|e| e.to_string())?;
                let chain = CertChain::from_hex(&chain).map_err(|e| e.to_string())?;
                chain.verify(&org_id, &me).map_err(|e| e.to_string())?;
                if chain.leaf().map(|l| l.issuer) != Some(adder) {
                    return Err("Welcome not from the certificate's issuer".into());
                }
                if let Some(Some(issuer)) = joining
                    && issuer != adder
                {
                    return Err("Welcome not from the device that answered our claim".into());
                }
                return Ok(());
            }
            Err("unexpected Welcome".into())
        }
    }

    /// The group forked between us and `peer` (ADR 0004).
    fn on_fork(
        &mut self,
        org: String,
        group: String,
        peer: String,
        we_win: bool,
    ) -> Result<Handled, ClientError> {
        let mut replies = vec![];
        if we_win {
            // Show the peer the commit we followed: it then sees it lost.
            if let Some(c) = self.groups.last_commit(&group) {
                replies.push(direct(
                    &org,
                    &peer,
                    sync::outer_body(&Outer::Commits {
                        group: group.clone(),
                        commits: vec![(c.committer, c.commit)],
                    }),
                ));
            }
        } else {
            let epoch = self.groups.epoch(&group)?;
            if self.readd_asked.get(&group) != Some(&epoch) {
                self.readd_asked.insert(group.clone(), epoch);
                replies.push(self.readd_request_frame(&org, &group, &peer)?);
            }
        }
        Ok(Handled {
            event: Event::Fork {
                org: group,
                peer,
                we_win,
            },
            replies,
        })
    }

    /// We are behind on `group`: ask `from` for the commits since `local`.
    fn behind(&self, org: String, group: String, from: String, local: u64) -> Handled {
        Handled {
            replies: vec![direct(
                &org,
                &from,
                sync::outer_body(&Outer::CommitRequest {
                    group: group.clone(),
                    epoch: local,
                }),
            )],
            event: Event::EpochBehind { org: group, from },
        }
    }

    /// The group (org or `org/subgroup` key) of an MLS message delivered for `org`;
    /// `None` if it is for another org, [`SUBGROUP_NOT_OURS`] for a subgroup of this
    /// org that we are not in.
    fn group_in(&self, org: &str, mls_message: &[u8]) -> Option<String> {
        let g = Groups::message_group(mls_message).ok()?;
        if !in_org(org, &g) {
            return None;
        }
        if g != org && !self.groups.has_group(&g) {
            return Some(SUBGROUP_NOT_OURS.into());
        }
        Some(g)
    }

    /// Send `to` the commits since `epoch`, or ask it to be re-added. Starts one
    /// epoch earlier when the log has it, so the peer can tell whether it followed
    /// the same commit out of its previous epoch (fork detection).
    fn serve_commits(
        &self,
        org: String,
        group: String,
        to: String,
        epoch: u64,
    ) -> Result<Handled, ClientError> {
        let since = match epoch.checked_sub(1) {
            Some(prev) if matches!(self.groups.commits_since(&group, prev), Ok(Some(_))) => prev,
            _ => epoch,
        };
        let (bodies, commits, readd_needed) = match self.groups.commits_since(&group, since) {
            Ok(Some(cs)) => {
                let n = cs.len();
                (sync::commits_bodies(&group, cs), n, false)
            }
            Ok(None) => (
                vec![sync::outer_body(&Outer::ReaddNeeded {
                    group: group.clone(),
                })],
                0,
                true,
            ),
            Err(e) => {
                return Ok(Handled::event(Event::Rejected {
                    org,
                    from: to,
                    reason: e.to_string(),
                }));
            }
        };
        Ok(Handled {
            replies: bodies.into_iter().map(|b| direct(&org, &to, b)).collect(),
            event: Event::CommitsServed {
                org: group,
                to,
                commits,
                readd_needed,
            },
        })
    }

    fn handle_app(
        &mut self,
        org: String,
        group: String,
        from: String,
        ct: &[u8],
    ) -> Result<Handled, ClientError> {
        // A sender at an older epoch missed commits: send them along (REQ-ENC-002).
        // The epoch is the message's unauthenticated header, so only for a member of
        // the group, and once per our epoch (it can still ask with `CommitRequest`).
        let help = match (Groups::message_epoch(ct), self.groups.epoch(&group)) {
            (Ok(theirs), Ok(ours))
                if theirs < ours
                    && self.trusted_member(&org, &group, &from)
                    && self.helped.get(&(group.clone(), from.clone())) != Some(&ours) =>
            {
                self.helped.insert((group.clone(), from.clone()), ours);
                self.serve_commits(org.clone(), group.clone(), from.clone(), theirs)?
                    .replies
            }
            _ => vec![],
        };
        let mut handled = match self.groups.decrypt(&group, ct) {
            Ok(d) if d.sender.to_hex() == from => {
                self.handle_plain(org, group, from, &d.plaintext)?
            }
            Ok(_) => Handled::event(Event::Rejected {
                org,
                from,
                reason: "MLS sender does not match the relay's sender".into(),
            }),
            Err(GroupError::EpochGap { local, .. }) => self.behind(org, group, from, local),
            Err(e) => {
                // A member's message for our own epoch that we cannot read means we
                // are on different branches of a fork: ask for its commits, which
                // start one epoch back and show the fork.
                let probe = self.same_epoch_member(&group, &from, ct);
                let mut h = Handled::event(Event::Rejected {
                    org: org.clone(),
                    from: from.clone(),
                    reason: e.to_string(),
                });
                if let Some(local) = probe {
                    h.replies.push(direct(
                        &org,
                        &from,
                        sync::outer_body(&Outer::CommitRequest {
                            group,
                            epoch: local,
                        }),
                    ));
                }
                h
            }
        };
        // Commits first, so the peer can read the encrypted replies that follow.
        handled.replies.splice(0..0, help);
        Ok(handled)
    }

    /// Our epoch, if `ct` is for it and `from` is a member of our view of the group.
    fn same_epoch_member(&self, org: &str, from: &str, ct: &[u8]) -> Option<u64> {
        let local = self.groups.epoch(org).ok()?;
        let member = self
            .groups
            .members(org)
            .ok()?
            .iter()
            .any(|d| d.to_hex() == from);
        (member && Groups::message_epoch(ct).ok()? == local).then_some(local)
    }

    /// `scope`: the group the message was encrypted for, which is also the scope
    /// its data belongs to.
    fn handle_plain(
        &mut self,
        org: String,
        scope: String,
        from: String,
        plaintext: &[u8],
    ) -> Result<Handled, ClientError> {
        use sync::Message;
        let rejected = |reason: String| {
            Handled::event(Event::Rejected {
                org: org.clone(),
                from: from.clone(),
                reason,
            })
        };
        let msg = match sync::parse(plaintext) {
            Ok(m) => m,
            Err(e) => return Ok(rejected(e)),
        };
        match msg {
            Message::Change(change) if change.body.scope.as_str() != scope => {
                Ok(rejected("change belongs to another scope".into()))
            }
            Message::Change(change) => match self.receive(change.clone()) {
                Ok(is_new) => Ok(Handled {
                    replies: if is_new {
                        self.eager_fetch(&org, &change)?
                    } else {
                        vec![]
                    },
                    event: Event::Received {
                        org,
                        from,
                        change: Box::new(change),
                        is_new,
                    },
                }),
                Err(ClientError::Rejected(e)) => Ok(rejected(e.to_string())),
                Err(ClientError::Forbidden(e)) => Ok(rejected(e)),
                Err(e) => Err(e),
            },
            Message::ChunkWant(ids) => {
                let (replies, sent, missing) = self.serve_chunks(&org, &scope, &from, &ids)?;
                Ok(Handled {
                    replies,
                    event: Event::ChunksServed {
                        to: from,
                        sent,
                        missing,
                    },
                })
            }
            Message::Chunks(chunks) => {
                let (stored, ready) = self.absorb_chunks(&scope, chunks)?;
                Ok(Handled::event(Event::FileChunks {
                    from,
                    stored,
                    ready,
                }))
            }
            Message::ChunkMissing(ids) => {
                // The peer the relay picked may not have the file: ask its author.
                let replies = self.ask_authors(&org, &scope, &from, &ids)?;
                Ok(Handled {
                    replies,
                    event: Event::ChunksMissing {
                        from,
                        count: ids.len(),
                    },
                })
            }
            Message::Query(query) => {
                match kith_sync::respond(&self.store.scope_ids(&org_scope(&scope)?)?, &query) {
                    Ok(answer) => {
                        let mut replies = vec![direct(
                            &org,
                            &from,
                            self.app_body(&scope, &sync::reply_body(&answer))?,
                        )];
                        // Catching up also hands over the notices we hold, so a
                        // new admin or always-on client learns them (ADR 0024).
                        if scope == org {
                            let held: Vec<String> = self
                                .revocations
                                .iter()
                                .filter(|r| r.org.to_hex() == org)
                                .map(Revocation::to_hex)
                                .collect();
                            for body in sync::notices_bodies(&held) {
                                replies.push(direct(&org, &from, self.app_body(&scope, &body)?));
                            }
                        }
                        Ok(Handled {
                            replies,
                            event: Event::SyncServed { from },
                        })
                    }
                    Err(e) => Ok(rejected(e.to_string())),
                }
            }
            Message::More => {
                // Another round with this peer (REQ-SYNC-005), unless one is running.
                if self.reconciling.contains_key(&scope) {
                    return Ok(Handled::event(Event::Ignored));
                }
                let body = self.start_reconcile(&scope, Some(&from))?;
                Ok(Handled {
                    replies: vec![direct(&org, &from, body)],
                    event: Event::Ignored,
                })
            }
            Message::Notices(lines) if scope == org => {
                self.learn_notices(&org, &lines)?;
                Ok(Handled::event(Event::Ignored))
            }
            Message::Notices(_) => Ok(rejected("notices belong to the org group".into())),
            Message::Reply(answer) => {
                let Some((r, peer)) = self.reconciling.get_mut(&scope) else {
                    // Not reconciling (any more): a late or duplicate answer.
                    return Ok(Handled::event(Event::Ignored));
                };
                // One reconciliation runs with one peer: the first to answer, or the
                // one we asked. Another member's answer would derail it.
                match peer {
                    Some(p) if *p != from => return Ok(Handled::event(Event::Ignored)),
                    Some(_) => {}
                    None => *peer = Some(from.clone()),
                }
                match r.step(&answer) {
                    Ok(kith_sync::Step::Continue(query)) => Ok(Handled {
                        replies: vec![direct(
                            &org,
                            &from,
                            self.app_body(&scope, &sync::query_body(&query))?,
                        )],
                        event: Event::Ignored,
                    }),
                    Ok(kith_sync::Step::Done(diff)) => {
                        self.reconciling.remove(&scope);
                        let (to_send, cut) = batch(self.changes_for(&scope, &diff.to_send)?);
                        // Ask for one batch; the peer sends `More` if it has further
                        // changes for us after answering.
                        let to_request =
                            &diff.to_request[..diff.to_request.len().min(SYNC_BATCH_CHANGES)];
                        let mut replies = if to_send.is_empty() && to_request.is_empty() {
                            vec![]
                        } else {
                            self.offer_frames(&org, &scope, &from, to_request, &to_send)?
                        };
                        if cut {
                            replies.push(self.more_frame(&org, &scope, &from)?);
                        }
                        Ok(Handled {
                            event: Event::SyncCompared {
                                from,
                                sending: to_send.len(),
                                wanting: to_request.len(),
                            },
                            replies,
                        })
                    }
                    Err(e) => {
                        self.reconciling.remove(&scope);
                        Ok(rejected(e.to_string()))
                    }
                }
            }
            Message::Offer { want, changes } => {
                let (mut stored, mut known, mut rejected_n) = (0, 0, 0);
                let mut fetches = vec![];
                for enc in changes {
                    let change = match kith_store::codec::decode_change(&enc) {
                        Ok(c) => c,
                        Err(_) => {
                            rejected_n += 1;
                            continue;
                        }
                    };
                    if change.body.scope.as_str() != scope {
                        rejected_n += 1;
                        continue;
                    }
                    match self.receive(change.clone()) {
                        Ok(true) => {
                            stored += 1;
                            fetches.extend(self.eager_fetch(&org, &change)?);
                        }
                        Ok(false) => known += 1,
                        Err(ClientError::Rejected(_) | ClientError::Forbidden(_)) => {
                            rejected_n += 1
                        }
                        Err(e) => return Err(e),
                    }
                }
                // Reply only if asked, so two offers never ping-pong forever.
                let mut replies = if want.is_empty() {
                    vec![]
                } else {
                    let (wanted, cut) = batch(self.changes_for(&scope, &want)?);
                    let mut r = self.offer_frames(&org, &scope, &from, &[], &wanted)?;
                    // The asker cut its list at one batch, or we cut our answer:
                    // tell it to reconcile again.
                    if cut || want.len() >= SYNC_BATCH_CHANGES {
                        r.push(self.more_frame(&org, &scope, &from)?);
                    }
                    r
                };
                replies.extend(fetches);
                Ok(Handled {
                    event: Event::SyncReceived {
                        from,
                        stored,
                        known,
                        rejected: rejected_n,
                        requested: want.len(),
                    },
                    replies,
                })
            }
        }
    }

    /// The stored changes of `org`'s scope with these IDs (unknown IDs and other
    /// scopes are skipped), oldest first. Includes changes the policy rejects: the
    /// peer must see them to reject them (and their dependents) too.
    fn changes_for(&self, scope: &str, ids: &[ChangeId]) -> Result<Vec<Change>, ClientError> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.store.get(id)?
                && c.body.scope.as_str() == scope
            {
                out.push(c);
            }
        }
        out.sort_by_key(|c| (c.body.timestamp_ms, c.change_id));
        Ok(out)
    }

    fn more_frame(&mut self, org: &str, scope: &str, to: &str) -> Result<Frame, ClientError> {
        Ok(direct(org, to, self.app_body(scope, &sync::more_body())?))
    }

    fn offer_frames(
        &mut self,
        org: &str,
        scope: &str,
        to: &str,
        want: &[ChangeId],
        changes: &[Change],
    ) -> Result<Vec<Frame>, ClientError> {
        sync::offer_bodies(want, changes)
            .into_iter()
            .map(|inner| Ok(direct(org, to, self.app_body(scope, &inner)?)))
            .collect()
    }

    /// The merged state of an object: all its changes, including concurrent
    /// forks, combined by `merger` (REQ-DATA-004). Does not change the store;
    /// the next `edit` names all current heads as parents, which joins forks.
    pub fn materialize<M: Merger>(
        &self,
        object: &ObjectId,
        merger: &M,
    ) -> Result<Materialized<M::State>, ClientError> {
        let hist = self.merge_history(object)?;
        if hist.is_empty() {
            return Err(ClientError::UnknownObject(*object));
        }
        Ok(merger.materialize(&hist)?)
    }

    /// Change history of an object: the changes the policy allows. Changes folded
    /// into a snapshot are gone (REQ-DATA-005); snapshots themselves are not listed.
    pub fn history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        let mut h = self.merge_history(object)?;
        h.retain(|c| !snapshot::is_snapshot(&c.body.payload));
        Ok(h)
    }

    /// Like [`Self::history`], but with the object's snapshots: what a [`Merger`]
    /// needs, because a snapshot carries the payloads of the changes it covers.
    fn merge_history(&self, object: &ObjectId) -> Result<Vec<Change>, ClientError> {
        let mut h = self.store.history(object)?;
        h.retain(|c| !self.invalid.contains(&c.change_id) && !self.covered.contains(&c.change_id));
        Ok(h)
    }

    /// The objects this device knows, as their creation changes (object ID, type, scope,
    /// author, creation time), oldest first; optionally only one `object_type`. Includes
    /// documents and file objects, not the internal policy object. Walks the whole store,
    /// so call it when building a list, not per frame.
    pub fn objects(&self, object_type: Option<&str>) -> Result<Vec<Change>, ClientError> {
        let mut out = Vec::new();
        for id in self.store.all_ids()? {
            let Some(c) = self.store.get(&id)? else {
                continue;
            };
            let ty = c.body.object_type.as_str();
            if c.is_creation()
                && ty != POLICY_TYPE
                && object_type.is_none_or(|t| t == ty)
                && !self.invalid.contains(&c.change_id)
            {
                out.push(c);
            }
        }
        out.sort_by_key(|c| (c.body.timestamp_ms, *c.change_id.as_bytes()));
        Ok(out)
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
