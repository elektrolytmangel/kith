//! Foreign-language bindings (UniFFI) for Swift and Kotlin.
//!
//! Keep this layer thin: convert types and errors, call into `kith-client`.
//! Anything with logic belongs in the Rust crates so every platform behaves
//! identically.

#![allow(missing_docs)] // UniFFI generates items

use std::sync::{Arc, Mutex};

use kith_client::{Client, DeviceKey, MemoryStore, ObjectId, ObjectType, Store};
use kith_store::SqliteStore;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KithError {
    #[error("{msg}")]
    Failed { msg: String },
}

macro_rules! into_kith_error {
    ($($t:ty),*) => {$(
        impl From<$t> for KithError {
            fn from(e: $t) -> Self {
                KithError::Failed { msg: e.to_string() }
            }
        }
    )*};
}
into_kith_error!(
    kith_client::ClientError,
    kith_client::IdError,
    kith_client::StoreError
);

type DynStore = Box<dyn Store + Send>;

fn seed_from(secret_key: Vec<u8>) -> Result<DeviceKey, KithError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|v: Vec<u8>| KithError::Failed {
            msg: format!("secret key must be 32 bytes, got {}", v.len()),
        })?;
    Ok(DeviceKey::from_secret_bytes(&seed))
}

/// A new random 32-byte device secret key. Save it in the platform's secure
/// storage before first use, then pass it to `KithClient.open`.
#[uniffi::export]
pub fn generate_secret_key() -> Vec<u8> {
    DeviceKey::generate().secret_bytes().to_vec()
}

/// Library version.
#[uniffi::export]
pub fn kith_version() -> String {
    kith_client::kith_core_version().to_string()
}

/// A change as seen by apps.
#[derive(uniffi::Record)]
pub struct ChangeInfo {
    pub change_id: String,
    pub object_id: String,
    pub object_type: String,
    pub author: String,
    pub timestamp_ms: u64,
    pub payload: Vec<u8>,
}

impl From<kith_client::Change> for ChangeInfo {
    fn from(c: kith_client::Change) -> Self {
        Self {
            change_id: c.change_id.to_hex(),
            object_id: c.body.object_id.to_hex(),
            object_type: c.body.object_type.0,
            author: c.author.to_hex(),
            timestamp_ms: c.body.timestamp_ms,
            payload: c.body.payload,
        }
    }
}

/// Client handle exposed to Swift/Kotlin.
#[derive(uniffi::Object)]
pub struct KithClient {
    inner: Mutex<Client<DynStore>>,
}

impl KithClient {
    /// The client. A panic in an earlier call (reported to Swift/Kotlin as an
    /// error) does not disable the handle for good: the lock is taken anyway, and
    /// the client's state is what that call had stored.
    fn lock(&self) -> std::sync::MutexGuard<'_, Client<DynStore>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[uniffi::export]
impl KithClient {
    /// New client with a fresh device key and in-memory store.
    ///
    /// The identity is lost when the client is dropped unless the app saves
    /// `secret_key()` and restores it with `with_secret_key`.
    /// For persistence use `open`.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(
                Client::new(
                    DeviceKey::generate(),
                    Box::new(MemoryStore::new()) as DynStore,
                )
                .expect("an empty memory store has no MLS state to load"),
            ),
        }
    }

    /// New client that restores a device identity from its 32-byte secret key
    /// (as returned by `secret_key()`), with an in-memory store.
    #[uniffi::constructor]
    pub fn with_secret_key(secret_key: Vec<u8>) -> Result<Self, KithError> {
        Ok(Self {
            inner: Mutex::new(Client::new(
                seed_from(secret_key)?,
                Box::new(MemoryStore::new()) as DynStore,
            )?),
        })
    }

    /// Persistent client: SQLite database at `db_path` (created if missing)
    /// and the device identity from `secret_key`. Reopening the same path with
    /// the same key restores all data, the identity and the MLS group state.
    /// The database holds group secrets: keep it in app-private storage.
    #[uniffi::constructor]
    pub fn open(db_path: String, secret_key: Vec<u8>) -> Result<Self, KithError> {
        let store = SqliteStore::open(db_path)?;
        Ok(Self {
            inner: Mutex::new(Client::new(
                seed_from(secret_key)?,
                Box::new(store) as DynStore,
            )?),
        })
    }

    /// Create an organization; returns its ID (the org root public key, hex). This
    /// device becomes its first admin and keeps the root key. Others join with an
    /// invite (`createInvite`, then `RelaySession.claim` on the new device).
    pub fn create_org(&self) -> Result<String, KithError> {
        Ok(self.lock().create_org()?)
    }

    /// True if this device may invite and admit devices to `org`.
    pub fn is_admin(&self, org: String) -> bool {
        self.lock().is_admin(&org)
    }

    /// A one-time invite link to `org`, valid for `ttl_seconds`, telling the new
    /// device to connect to `relay`. Admins only; keep this device online until the
    /// claim arrives (`InviteClaimed`).
    pub fn create_invite(
        &self,
        org: String,
        relay: String,
        ttl_seconds: u64,
    ) -> Result<String, KithError> {
        Ok(self
            .lock()
            .create_invite(&org, &relay, ttl_seconds.saturating_mul(1000))?)
    }

    /// A one-time link to add another device of *this user* to `org`, valid for
    /// `ttl_seconds`. Any member can make one, not only admins. The new device gets
    /// this device's role (at most editor); accept it with `acceptClaim` like any
    /// claim. Not available on a device that was itself added this way.
    pub fn create_own_device_invite(
        &self,
        org: String,
        relay: String,
        ttl_seconds: u64,
    ) -> Result<String, KithError> {
        Ok(self
            .lock()
            .create_own_device_invite(&org, &relay, ttl_seconds.saturating_mul(1000))?)
    }

    /// True if this device is a member of `org`'s group (it can send and read).
    pub fn is_member(&self, org: String) -> bool {
        self.lock().is_member(&org)
    }

    /// Devices (hex IDs) in `org`'s group.
    pub fn group_members(&self, org: String) -> Result<Vec<String>, KithError> {
        Ok(self.lock().group_members(&org)?)
    }

    /// Restore a device from a backup made with `exportBackup` into a new SQLite
    /// database at `db_path`. Same identity and data; it rejoins its groups (fresh
    /// keys) once a member is online. Only when the original device is gone.
    #[uniffi::constructor]
    pub fn restore(
        db_path: String,
        backup: Vec<u8>,
        passphrase: String,
    ) -> Result<Self, KithError> {
        let store = SqliteStore::open(db_path)?;
        let c = Client::import_backup(&backup, &passphrase, Box::new(store) as DynStore)?;
        Ok(Self {
            inner: Mutex::new(c),
        })
    }

    /// A passphrase-encrypted backup of this device (identity, data, files,
    /// memberships). Anyone with it and the passphrase can act as this device.
    pub fn export_backup(&self, passphrase: String) -> Result<Vec<u8>, KithError> {
        Ok(self.lock().export_backup(&passphrase)?)
    }

    /// The 32-byte secret key of this device. Store it only in the platform's
    /// secure storage (Keychain, Android Keystore); anyone who has it can
    /// sign as this device.
    pub fn secret_key(&self) -> Vec<u8> {
        self.lock().signer().secret_bytes().to_vec()
    }

    pub fn device_id(&self) -> String {
        self.lock().device_id().to_hex()
    }

    pub fn create(&self, object_type: String, payload: Vec<u8>) -> Result<ChangeInfo, KithError> {
        let c = self
            .inner
            .lock()
            .unwrap()
            .create(ObjectType::new(object_type), payload)?;
        Ok(c.into())
    }

    /// Store a file (encrypted, in chunks) in the default scope; returns the
    /// `kith.file` change to broadcast. Peers fetch the chunks with `fetchFile`.
    pub fn add_file(
        &self,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Result<ChangeInfo, KithError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .add_file(&name, &mime, &data)?
            .into())
    }

    /// `addFile` in `scope` (an org ID, `org/subgroup`, or `local`).
    pub fn add_file_in(
        &self,
        scope: String,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Result<ChangeInfo, KithError> {
        let scope = kith_client::Scope::parse(&scope)
            .map_err(|e| KithError::Failed { msg: e.to_string() })?;
        Ok(self
            .inner
            .lock()
            .unwrap()
            .add_file_in(scope, &name, &mime, &data)?
            .into())
    }

    /// Name, MIME type, size and missing chunk count of a file object.
    pub fn file_info(&self, object_id: String) -> Result<FileInfoRecord, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        let i = self.lock().file_info(&oid)?;
        Ok(FileInfoRecord {
            name: i.name,
            mime: i.mime,
            size: i.size,
            chunks: i.chunks as u64,
            missing: i.missing as u64,
        })
    }

    /// The contents of a file whose chunks are all here (fetch it first).
    pub fn read_file(&self, object_id: String) -> Result<Vec<u8>, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        Ok(self.lock().read_file(&oid)?)
    }

    /// Fetch every new file's chunks as soon as it arrives (default: only on `fetchFile`).
    pub fn set_fetch_files(&self, eager: bool) {
        self.lock().set_fetch_files(eager);
    }

    /// Create an object in `scope`: an org ID (or `org/subgroup`) this device is a
    /// member of, or `local`. `create` uses the only org, or `local` before joining.
    pub fn create_in(
        &self,
        scope: String,
        object_type: String,
        payload: Vec<u8>,
    ) -> Result<ChangeInfo, KithError> {
        let scope = kith_client::Scope::parse(&scope)
            .map_err(|e| KithError::Failed { msg: e.to_string() })?;
        let c =
            self.inner
                .lock()
                .unwrap()
                .create_in(scope, ObjectType::new(object_type), payload)?;
        Ok(c.into())
    }

    pub fn edit(&self, object_id: String, payload: Vec<u8>) -> Result<ChangeInfo, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        Ok(self.lock().edit(oid, payload)?.into())
    }

    pub fn history(&self, object_id: String) -> Result<Vec<ChangeInfo>, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        let h = self.lock().history(&oid)?;
        Ok(h.into_iter().map(Into::into).collect())
    }

    /// The objects this device knows, as their creation changes (object ID, type, author,
    /// creation time), oldest first. Pass an object type to list only those.
    pub fn objects(&self, object_type: Option<String>) -> Result<Vec<ChangeInfo>, KithError> {
        let list = self.lock().objects(object_type.as_deref())?;
        Ok(list.into_iter().map(Into::into).collect())
    }

    /// Create a JSON document (an object whose edits merge without conflicts, see
    /// `updateDocument`). `json` must be a JSON object. Broadcast the change like any other.
    pub fn create_document(
        &self,
        object_type: String,
        json: String,
    ) -> Result<ChangeInfo, KithError> {
        let c = self
            .inner
            .lock()
            .unwrap()
            .create_document(ObjectType::new(object_type), &json)?;
        Ok(c.into())
    }

    /// Change a document with a JSON merge patch (RFC 7396: `null` removes a key,
    /// objects merge, other values replace). Edits of different keys on different
    /// devices all survive. `nil`/`null` if the patch changes nothing.
    pub fn update_document(
        &self,
        object_id: String,
        patch: String,
    ) -> Result<Option<ChangeInfo>, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        Ok(self
            .inner
            .lock()
            .unwrap()
            .update_document(oid, &patch)?
            .map(Into::into))
    }

    /// The merged state of a document as a JSON string (all devices' edits).
    pub fn document_json(&self, object_id: String) -> Result<String, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        Ok(self.lock().document_json(&oid)?)
    }
}

/// What happened when a frame from the relay was handled.
#[derive(uniffi::Enum)]
pub enum RelayEvent {
    /// A peer's change was valid and is stored. `is_new` is false if it was already known.
    Received {
        org: String,
        from: String,
        object_id: String,
        change_id: String,
        is_new: bool,
    },
    /// A peer's message was refused (not decryptable, unencrypted, bad hash or
    /// signature); nothing was stored.
    Rejected {
        org: String,
        from: String,
        reason: String,
    },
    /// We answered a round of a peer's catch-up request.
    SyncServed { from: String },
    /// Our catch-up is reconciled: we sent `from` the `sending` changes it lacks and
    /// asked for the `wanting` changes we lack (they arrive as `SyncReceived`).
    /// Both zero: in sync with that peer.
    SyncCompared {
        from: String,
        sending: u64,
        wanting: u64,
    },
    /// A peer sent changes for catch-up: `stored` are new. `requested` is how many it
    /// asked us to send back (the replies are in `SessionOutput.replies`).
    SyncReceived {
        from: String,
        stored: u64,
        known: u64,
        rejected: u64,
        requested: u64,
    },
    /// Devices currently online in an organization.
    Presence { org: String, online: Vec<String> },
    /// Which devices a broadcast of ours reached.
    Receipt { delivered: Vec<String> },
    /// The relay refused something (for example `auth-failed`, after which it closes).
    RelayError { code: String, message: String },
    /// A device claimed one of our invites with a valid proof. Compare `code` with
    /// the new device's screen if you want, then `RelaySession.acceptClaim(from)` (or
    /// `rejectClaim`).
    InviteClaimed {
        org: String,
        from: String,
        code: String,
    },
    /// We got a new membership certificate (for example admin rights).
    CertificateUpdated { org: String, admin: bool },
    /// This device joined `org`; the history is requested by the replies.
    Joined { org: String },
    /// A commit changed `org`'s group. `removed`: this device was removed.
    GroupChanged {
        org: String,
        epoch: u64,
        removed: bool,
    },
    /// This device missed group commits; the replies ask `from` for them.
    EpochBehind { org: String, from: String },
    /// We sent commits to a peer that was behind, or (`readd_needed`) asked it to rejoin.
    CommitsServed {
        org: String,
        to: String,
        commits: u64,
        readd_needed: bool,
    },
    /// We applied commits we had missed.
    CommitsApplied {
        org: String,
        from: String,
        applied: u64,
        epoch: u64,
    },
    /// We were too far behind and asked `from` to re-add us.
    ReAddRequested { org: String, from: String },
    /// We re-added `device`, which had fallen too far behind.
    MemberReAdded { org: String, device: String },
    /// We (a subgroup's owner) added `device` to subgroup `org` (`<org>/<name>`).
    MemberAdded { org: String, device: String },
    /// We sent a peer the file chunks it asked for.
    ChunksServed { to: String, sent: u64, missing: u64 },
    /// File chunks arrived; `ready` lists file object IDs that are now complete.
    FileChunks {
        from: String,
        stored: u64,
        ready: Vec<String>,
    },
    /// The asked peer lacks `count` chunks; try again later.
    ChunksMissing { from: String, count: u64 },
    /// Two members changed the group at the same time. `we_win` false: this device
    /// asked `peer` to re-add it (data catches up afterwards); nothing to do for the app.
    Fork {
        org: String,
        peer: String,
        we_win: bool,
    },
}

/// What `KithClient.fileInfo` reports.
#[derive(uniffi::Record)]
pub struct FileInfoRecord {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub chunks: u64,
    /// Chunks not on this device yet (0: `readFile` works).
    pub missing: u64,
}

/// Result of [`RelaySession::claim`].
#[derive(uniffi::Record)]
pub struct ClaimOutput {
    /// The claim frame to send.
    pub frame: Vec<u8>,
    /// The short code to show; the admin sees the same in `InviteClaimed`.
    pub code: String,
}

/// What an invite link points to.
#[derive(uniffi::Record)]
pub struct InviteInfo {
    /// The org ID: open the `RelaySession` for it.
    pub org: String,
    /// The relay to connect to.
    pub relay: String,
    /// Expiry, milliseconds since the Unix epoch.
    pub expires_ms: u64,
}

/// Read an invite link without claiming it, to know which relay and org to connect to.
#[uniffi::export]
pub fn parse_invite(link: String) -> Result<InviteInfo, KithError> {
    let inv =
        kith_client::Invite::parse(&link).map_err(|e| KithError::Failed { msg: e.to_string() })?;
    Ok(InviteInfo {
        org: inv.org.to_hex(),
        relay: inv.relay,
        expires_ms: inv.expires_ms,
    })
}

/// Result of [`RelaySession::receive`].
#[derive(uniffi::Record)]
pub struct SessionOutput {
    /// Frames to send to the relay right away, in order.
    pub replies: Vec<Vec<u8>>,
    /// What the frame meant for the app, if anything.
    pub event: Option<RelayEvent>,
}

/// Live sync with one organization through a relay, without owning the socket.
///
/// The app opens a WebSocket (`URLSessionWebSocketTask`, OkHttp, ...) to the
/// relay's `/v1/ws`, sends [`hello`](Self::hello) when it opens, passes every
/// binary message to [`receive`](Self::receive) and sends the returned
/// `replies`. After `create`/`edit`, send [`broadcast`](Self::broadcast).
/// Only online devices are reached. Every body is encrypted for the org's MLS
/// group, so the device must be a member: `KithClient.createGroup` on the first
/// device, [`join_request`](Self::join_request) + [`add_member`](Self::add_member)
/// for the others.
#[derive(uniffi::Object)]
pub struct RelaySession {
    client: Arc<KithClient>,
    org: String,
}

#[uniffi::export]
impl KithClient {
    /// Start live sync with `org`. See [`RelaySession`].
    pub fn relay_session(self: Arc<Self>, org: String) -> Arc<RelaySession> {
        Arc::new(RelaySession { client: self, org })
    }
}

#[uniffi::export]
impl RelaySession {
    /// The first frame to send once the WebSocket is open.
    pub fn hello(&self) -> Result<Vec<u8>, KithError> {
        let c = self.client.lock();
        encode_frame(&kith_client::hello_frame(c.signer()))
    }

    /// Handle one binary message from the relay: answers the handshake, validates
    /// and stores peers' changes. A bad change from a peer is an
    /// `Event::Rejected`, not an error; an error means the frame itself was
    /// malformed or local storage failed.
    pub fn receive(&self, frame: Vec<u8>) -> Result<SessionOutput, KithError> {
        let frame =
            kith_protocol::decode(&frame).map_err(|e| KithError::Failed { msg: e.to_string() })?;
        let mut c = self.client.lock();
        if let Some(replies) = c.handshake_reply(&self.org, &frame) {
            return Ok(SessionOutput {
                replies: replies.iter().map(encode_frame).collect::<Result<_, _>>()?,
                event: None,
            });
        }
        let handled = c.handle_frame(frame)?;
        Ok(SessionOutput {
            replies: handled
                .replies
                .iter()
                .map(encode_frame)
                .collect::<Result<_, _>>()?,
            event: relay_event(handled.event),
        })
    }

    /// The frame that asks one online peer for the changes this device lacks and
    /// offers it ours (catch-up). Send it after the connection is up (for example
    /// once a `Presence` event shows another device); also use it on a new device
    /// to download the full history. The relay's `Receipt` event has an empty
    /// `delivered` list if nobody was online. Answers arrive through `receive`.
    /// Also covers the subgroups this device is in. Send all frames.
    pub fn catch_up(&self) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.sync_request_frames(&self.org)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Create read-restricted subgroup `name` with `members` (hex IDs; admins
    /// only). Data created with `createIn("<org>/<name>", ...)` only reaches its
    /// members. This device runs the subgroup and must be online for members to be
    /// added. Send all frames.
    pub fn create_subgroup(
        &self,
        name: String,
        members: Vec<String>,
    ) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.create_subgroup(&self.org, &name, &members)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Replace the members of subgroup `name` (admins only). Send all frames.
    pub fn set_subgroup_members(
        &self,
        name: String,
        members: Vec<String>,
    ) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.set_subgroup_members(&self.org, &name, &members)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Members of subgroup `name` per the policy (`nil`/`null` if it does not exist).
    pub fn subgroup_members(&self, name: String) -> Option<Vec<String>> {
        self.client
            .inner
            .lock()
            .unwrap()
            .subgroup_members(&self.org, &name)
    }

    /// Subgroups of this org this device can read.
    pub fn my_subgroups(&self) -> Vec<String> {
        self.client.lock().my_subgroups(&self.org)
    }

    /// Frames that fetch the missing chunks of a file from a peer. `FileChunks`
    /// events report progress; `ready` lists files that are complete.
    pub fn fetch_file(&self, object_id: String) -> Result<Vec<Vec<u8>>, KithError> {
        let oid = ObjectId::from_hex(&object_id)?;
        let mut c = self.client.lock();
        c.fetch_file_frames(&self.org, &oid)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Claim an invite link (on the new device; open this session for the link's
    /// org, see `parseInvite`). Send `frame`, show `code`, wait for `Joined`.
    pub fn claim(&self, link: String) -> Result<ClaimOutput, KithError> {
        let mut c = self.client.lock();
        let claim = c.claim_invite(&link)?;
        if claim.org != self.org {
            return Err(KithError::Failed {
                msg: format!(
                    "invite is for org {}, session is for {}",
                    claim.org, self.org
                ),
            });
        }
        Ok(ClaimOutput {
            frame: encode_frame(&claim.frame)?,
            code: claim.code,
        })
    }

    /// Admit the device of an `InviteClaimed` event. Send all returned frames, in order.
    pub fn accept_claim(&self, device: String) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.accept_claim(&self.org, &device)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Refuse the claim of an `InviteClaimed` event; the invite stays valid.
    pub fn reject_claim(&self, device: String) {
        self.client
            .inner
            .lock()
            .unwrap()
            .reject_claim(&self.org, &device);
    }

    /// Make a member an admin (only the org's creator can). Send the returned
    /// frames in order.
    pub fn grant_admin(&self, device: String) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.grant_admin(&self.org, &device)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Remove `device` (hex) from the org: out of the encrypted group and revoked
    /// in the policy (admins only). Send the returned frames in order.
    pub fn remove_member(&self, device: String) -> Result<Vec<Vec<u8>>, KithError> {
        let mut c = self.client.lock();
        c.remove_member(&self.org, &device)?
            .iter()
            .map(encode_frame)
            .collect()
    }

    /// Set a member's role (`viewer`, `editor`, `admin`; admin only from the org's
    /// creator). Admins only. Send the returned frame.
    pub fn set_role(&self, device: String, role: String) -> Result<Vec<u8>, KithError> {
        let role = parse_role(&role)?;
        let mut c = self.client.lock();
        let change = c.set_role(&self.org, &device, role)?;
        encode_frame(&c.broadcast_frame(&self.org, &change)?)
    }

    /// Set the minimum role (`viewer`, `editor`, `admin`) that may write objects of
    /// `object_type`. Admins only. Send the returned frame.
    pub fn set_write_rule(&self, object_type: String, role: String) -> Result<Vec<u8>, KithError> {
        let role = parse_role(&role)?;
        let mut c = self.client.lock();
        let change = c.set_write_rule(&self.org, &object_type, role)?;
        encode_frame(&c.broadcast_frame(&self.org, &change)?)
    }

    /// A device's role: `viewer`, `editor`, `admin`, or `nil`/`null` if revoked.
    pub fn role_of(&self, device: String) -> Result<Option<String>, KithError> {
        let c = self.client.lock();
        Ok(c.role_of(&self.org, &device)?
            .map(|r| r.as_str().to_string()))
    }

    /// Rotate this device's group key (do it periodically, e.g. weekly). Send the
    /// returned frame.
    pub fn rotate_key(&self) -> Result<Vec<u8>, KithError> {
        let mut c = self.client.lock();
        encode_frame(&c.rotate_key(&self.org)?)
    }

    /// The frame that tells the other online devices about a local change
    /// (as returned by `create`/`edit`), encrypted for the org's group.
    pub fn broadcast(&self, change_id: String) -> Result<Vec<u8>, KithError> {
        let id = kith_client::ChangeId::from_hex(&change_id)?;
        let mut c = self.client.lock();
        let change = c.store().get(&id)?.ok_or_else(|| KithError::Failed {
            msg: format!("unknown change {change_id}"),
        })?;
        encode_frame(&c.broadcast_frame(&self.org, &change)?)
    }
}

fn parse_role(s: &str) -> Result<kith_client::Role, KithError> {
    kith_client::Role::parse(s).ok_or_else(|| KithError::Failed {
        msg: format!("unknown role {s:?}: use viewer, editor or admin"),
    })
}

fn encode_frame(f: &kith_protocol::Frame) -> Result<Vec<u8>, KithError> {
    kith_protocol::encode(f).map_err(|e| KithError::Failed { msg: e.to_string() })
}

fn relay_event(ev: kith_client::Event) -> Option<RelayEvent> {
    use kith_client::Event;
    Some(match ev {
        Event::Received {
            org,
            from,
            change,
            is_new,
        } => RelayEvent::Received {
            org,
            from,
            object_id: change.body.object_id.to_hex(),
            change_id: change.change_id.to_hex(),
            is_new,
        },
        Event::Rejected { org, from, reason } => RelayEvent::Rejected { org, from, reason },
        Event::SyncServed { from } => RelayEvent::SyncServed { from },
        Event::SyncCompared {
            from,
            sending,
            wanting,
        } => RelayEvent::SyncCompared {
            from,
            sending: sending as u64,
            wanting: wanting as u64,
        },
        Event::SyncReceived {
            from,
            stored,
            known,
            rejected,
            requested,
        } => RelayEvent::SyncReceived {
            from,
            stored: stored as u64,
            known: known as u64,
            rejected: rejected as u64,
            requested: requested as u64,
        },
        Event::Presence { org, online } => RelayEvent::Presence { org, online },
        Event::Receipt { delivered } => RelayEvent::Receipt { delivered },
        Event::RelayError { code, message } => RelayEvent::RelayError { code, message },
        Event::InviteClaimed { org, from, code } => RelayEvent::InviteClaimed { org, from, code },
        Event::CertificateUpdated { org, admin } => RelayEvent::CertificateUpdated { org, admin },
        Event::Joined { org } => RelayEvent::Joined { org },
        Event::GroupChanged {
            org,
            epoch,
            removed,
        } => RelayEvent::GroupChanged {
            org,
            epoch,
            removed,
        },
        Event::EpochBehind { org, from } => RelayEvent::EpochBehind { org, from },
        Event::CommitsServed {
            org,
            to,
            commits,
            readd_needed,
        } => RelayEvent::CommitsServed {
            org,
            to,
            commits: commits as u64,
            readd_needed,
        },
        Event::CommitsApplied {
            org,
            from,
            applied,
            epoch,
        } => RelayEvent::CommitsApplied {
            org,
            from,
            applied: applied as u64,
            epoch,
        },
        Event::ReAddRequested { org, from } => RelayEvent::ReAddRequested { org, from },
        Event::MemberReAdded { org, device } => RelayEvent::MemberReAdded { org, device },
        Event::MemberAdded { org, device } => RelayEvent::MemberAdded { org, device },
        Event::ChunksServed { to, sent, missing } => RelayEvent::ChunksServed {
            to,
            sent: sent as u64,
            missing: missing as u64,
        },
        Event::FileChunks {
            from,
            stored,
            ready,
        } => RelayEvent::FileChunks {
            from,
            stored: stored as u64,
            ready: ready.iter().map(|o| o.to_hex()).collect(),
        },
        Event::ChunksMissing { from, count } => RelayEvent::ChunksMissing {
            from,
            count: count as u64,
        },
        Event::Fork { org, peer, we_win } => RelayEvent::Fork { org, peer, we_win },
        Event::Ignored => return None,
    })
}

impl Default for KithClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// req: REQ-PLAT-002
    #[test]
    fn restored_key_keeps_device_identity() {
        let a = KithClient::new();
        let b = KithClient::with_secret_key(a.secret_key()).unwrap();
        assert_eq!(a.device_id(), b.device_id());
        let c = b.create("note".into(), b"x".to_vec()).unwrap();
        assert_eq!(c.author, a.device_id());
        assert_ne!(KithClient::new().device_id(), a.device_id());
    }

    /// req: REQ-PLAT-002
    /// req: REQ-STORE-001
    #[test]
    fn open_persists_data_and_identity() {
        let dir = std::env::temp_dir().join(format!(
            "kith-ffi-{}",
            generate_secret_key()[0..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kith.db").to_string_lossy().into_owned();
        let key = generate_secret_key();

        let first = KithClient::open(path.clone(), key.clone()).unwrap();
        let created = first.create("note".into(), b"v1".to_vec()).unwrap();
        first
            .edit(created.object_id.clone(), b"v2".to_vec())
            .unwrap();
        let device = first.device_id();
        drop(first);

        let second = KithClient::open(path, key).unwrap();
        assert_eq!(second.device_id(), device);
        assert_eq!(second.history(created.object_id).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// req: REQ-DATA-006
    #[test]
    fn backups_restore_into_a_new_database() {
        let a = KithClient::new();
        let note = a.create("note".into(), b"keep me".to_vec()).unwrap();
        let backup = a.export_backup("pw".into()).unwrap();
        let dir = std::env::temp_dir().join(format!("kith-ffi-restore-{}", note.change_id));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kith.db").to_string_lossy().into_owned();
        assert!(KithClient::restore(path.clone(), backup.clone(), "nope".into()).is_err());
        let b = KithClient::restore(path, backup, "pw".into()).unwrap();
        assert_eq!(b.device_id(), a.device_id());
        assert_eq!(b.history(note.object_id).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_rejects_bad_key_and_bad_path() {
        assert!(KithClient::open("/nonexistent-dir/x.db".into(), generate_secret_key()).is_err());
        assert!(KithClient::open(":memory:".into(), vec![1; 5]).is_err());
    }

    /// Deliver a frame one session sent to the other, as the relay would.
    fn relay_to(from: &KithClient, to: &RelaySession, frame: &[u8]) -> SessionOutput {
        use kith_protocol::Frame;
        let deliver = match kith_protocol::decode(frame).unwrap() {
            Frame::InviteClaim { org, body, .. } => Frame::ClaimDeliver {
                org,
                from: from.device_id(),
                body,
            },
            Frame::SyncRequest { org, body }
            | Frame::Broadcast { org, body }
            | Frame::Direct { org, body, .. } => Frame::Deliver {
                org,
                from: from.device_id(),
                body,
            },
            _ => panic!("frame with a body expected"),
        };
        to.receive(kith_protocol::encode(&deliver).unwrap())
            .unwrap()
    }

    /// `a` invites `b`, `b` claims, `a` accepts. Returns the replies `b` sent after
    /// joining (its announcement with the certificate, then its catch-up request).
    fn join(
        a: &Arc<KithClient>,
        sa: &RelaySession,
        b: &Arc<KithClient>,
        sb: &RelaySession,
    ) -> Vec<Vec<u8>> {
        let org = sa.org.clone();
        let link = a
            .create_invite(org.clone(), "ws://relay/v1/ws".into(), 60)
            .unwrap();
        let info = parse_invite(link.clone()).unwrap();
        assert_eq!(
            (info.org.as_str(), info.relay.as_str()),
            (org.as_str(), "ws://relay/v1/ws")
        );
        let claim = sb.claim(link).unwrap();
        let out = relay_to(b, sa, &claim.frame);
        let Some(RelayEvent::InviteClaimed { from, code, .. }) = out.event else {
            panic!("claim expected")
        };
        assert_eq!(code, claim.code);
        let frames = sa.accept_claim(from).unwrap();
        assert_eq!(frames.len(), 3, "b named in the policy + commit + welcome");
        // The commit reaches b before it is a member; the Welcome then adds it.
        // (The policy change, in the old epoch, reaches b with the catch-up.)
        let _ = relay_to(a, sb, &frames[1]);
        let out = relay_to(a, sb, &frames[2]);
        assert!(matches!(out.event, Some(RelayEvent::Joined { .. })));
        assert!(b.is_member(org.clone()));
        assert_eq!(a.group_members(org).unwrap().len(), 2);
        assert_eq!(out.replies.len(), 2);
        assert!(matches!(
            kith_protocol::decode(&out.replies[0]).unwrap(),
            kith_protocol::Frame::Announce { orgs } if !orgs[0].proof.is_empty()
        ));
        out.replies[1..].to_vec()
    }

    /// Relay `frames` sent by `first` back and forth until nobody replies.
    fn bounce(
        first: (&KithClient, &RelaySession),
        second: (&KithClient, &RelaySession),
        frames: Vec<Vec<u8>>,
    ) {
        let mut queue: Vec<(bool, Vec<u8>)> = frames.into_iter().map(|f| (true, f)).collect();
        while let Some((from_first, f)) = queue.pop() {
            let (from, to) = if from_first {
                (first, second)
            } else {
                (second, first)
            };
            let out = relay_to(from.0, to.1, &f);
            queue.extend(out.replies.into_iter().map(|r| (!from_first, r)));
        }
    }

    /// `a` created an org; sessions for it on `a` and `b` (not a member yet).
    fn pair() -> (
        Arc<KithClient>,
        Arc<RelaySession>,
        Arc<KithClient>,
        Arc<RelaySession>,
    ) {
        let a = Arc::new(KithClient::new());
        let b = Arc::new(KithClient::new());
        let org = a.create_org().unwrap();
        assert!(a.is_admin(org.clone()));
        let sa = a.clone().relay_session(org.clone());
        let sb = b.clone().relay_session(org);
        (a, sa, b, sb)
    }

    /// req: REQ-SYNC-004
    /// req: REQ-ENC-001
    #[test]
    fn sessions_exchange_encrypted_changes_through_frames() {
        let (a, sa, b, sb) = pair();

        // Handshake: hello -> (relay) challenge -> auth + announce.
        let hello = kith_protocol::decode(&sa.hello().unwrap()).unwrap();
        assert!(matches!(hello, kith_protocol::Frame::Hello { .. }));
        let challenge =
            kith_protocol::encode(&kith_protocol::Frame::Challenge { nonce: "ab".into() }).unwrap();
        let out = sa.receive(challenge).unwrap();
        assert!(out.event.is_none());
        let frames: Vec<_> = out
            .replies
            .iter()
            .map(|f| kith_protocol::decode(f).unwrap())
            .collect();
        assert!(matches!(frames[0], kith_protocol::Frame::Auth { .. }));
        assert!(matches!(frames[1], kith_protocol::Frame::Announce { .. }));

        // Not a member yet: nothing can be sent.
        let early = b.create("note".into(), b"early".to_vec()).unwrap();
        assert!(sb.broadcast(early.change_id).is_err());
        join(&a, &sa, &b, &sb);

        // A change made on a reaches b.
        let created = a.create("note".into(), b"v1".to_vec()).unwrap();
        let broadcast = sa.broadcast(created.change_id.clone()).unwrap();
        let out = relay_to(&a, &sb, &broadcast);
        match out.event {
            Some(RelayEvent::Received {
                object_id,
                change_id,
                is_new,
                from,
                ..
            }) => {
                assert_eq!(object_id, created.object_id);
                assert_eq!(change_id, created.change_id);
                assert_eq!(from, a.device_id());
                assert!(is_new);
            }
            _ => panic!("expected a received event"),
        }
        assert_eq!(b.history(created.object_id).unwrap().len(), 1);
        assert!(sa.broadcast("00".repeat(32)).is_err(), "unknown change");
        // Key rotation and removal produce frames.
        let rotate = relay_to(&b, &sa, &sb.rotate_key().unwrap());
        assert!(matches!(
            rotate.event,
            Some(RelayEvent::GroupChanged { removed: false, .. })
        ));
        // Roles: b first catches up (it gets the policy), then a demotes and removes it.
        bounce((&b, &sb), (&a, &sa), sb.catch_up().unwrap());
        let demote = relay_to(
            &a,
            &sb,
            &sa.set_role(b.device_id(), "viewer".into()).unwrap(),
        );
        assert!(matches!(demote.event, Some(RelayEvent::Received { .. })));
        assert_eq!(
            sb.role_of(b.device_id()).unwrap().as_deref(),
            Some("viewer")
        );
        assert!(b.create("note".into(), b"no".to_vec()).is_err());
        assert!(sa.set_role(b.device_id(), "boss".into()).is_err());
        assert!(
            sb.set_write_rule("note".into(), "viewer".into()).is_err(),
            "not an admin"
        );
        let frames = sa.remove_member(b.device_id()).unwrap();
        let removal = relay_to(&a, &sb, &frames[0]);
        assert!(matches!(
            removal.event,
            Some(RelayEvent::GroupChanged { removed: true, .. })
        ));
        assert_eq!(sa.role_of(b.device_id()).unwrap(), None);
    }

    /// req: REQ-SYNC-003
    #[test]
    fn joining_downloads_the_history_into_an_empty_client() {
        let (a, sa, b, sb) = pair();
        let created = a.create("note".into(), b"v1".to_vec()).unwrap();
        a.edit(created.object_id.clone(), b"v2".to_vec()).unwrap();

        // Joining asks for the history on its own: a answers the reconciliation,
        // b asks for the 2 changes it lacks, a sends them.
        let replies = join(&a, &sa, &b, &sb);
        assert_eq!(replies.len(), 1);
        let served = relay_to(&b, &sa, &replies[0]);
        assert!(matches!(served.event, Some(RelayEvent::SyncServed { .. })));
        let compared = relay_to(&a, &sb, &served.replies[0]);
        assert!(
            matches!(
                compared.event,
                Some(RelayEvent::SyncCompared { wanting: 4, .. })
            ),
            "2 notes + the policy genesis + b named in the policy"
        );
        let asked = relay_to(&b, &sa, &compared.replies[0]);
        assert!(matches!(
            asked.event,
            Some(RelayEvent::SyncReceived { requested: 4, .. })
        ));
        let received = relay_to(&a, &sb, &asked.replies[0]);
        assert!(matches!(
            received.event,
            Some(RelayEvent::SyncReceived { stored: 4, .. })
        ));
        assert_eq!(b.history(created.object_id.clone()).unwrap().len(), 2);
        // And catch_up works the same way later: nothing to do now.
        let served = relay_to(&b, &sa, &sb.catch_up().unwrap()[0]);
        let compared = relay_to(&a, &sb, &served.replies[0]);
        assert!(matches!(
            compared.event,
            Some(RelayEvent::SyncCompared {
                sending: 0,
                wanting: 0,
                ..
            })
        ));
    }

    /// req: REQ-SYNC-004
    /// req: REQ-ENC-001
    #[test]
    fn tampered_and_garbage_frames_do_not_store_anything() {
        let (a, sa, b, sb) = pair();
        join(&a, &sa, &b, &sb);
        let created = a.create("note".into(), b"v1".to_vec()).unwrap();
        let broadcast = sa.broadcast(created.change_id).unwrap();
        let kith_protocol::Frame::Broadcast { org, mut body } =
            kith_protocol::decode(&broadcast).unwrap()
        else {
            panic!()
        };
        *body.last_mut().unwrap() ^= 1;
        let tampered = kith_protocol::encode(&kith_protocol::Frame::Deliver {
            org,
            from: a.device_id(),
            body,
        })
        .unwrap();
        let out = sb.receive(tampered).unwrap();
        assert!(matches!(out.event, Some(RelayEvent::Rejected { .. })));
        assert!(sb.receive(b"not a frame".to_vec()).is_err());
        assert!(b.history(created.object_id).unwrap().is_empty());
    }

    /// req: REQ-FILE-002
    #[test]
    fn files_through_sessions() {
        let (a, sa, b, sb) = pair();
        let catch_up = join(&a, &sa, &b, &sb);
        bounce((&b, &sb), (&a, &sa), catch_up);
        let data: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let f = a
            .add_file(
                "x.bin".into(),
                "application/octet-stream".into(),
                data.clone(),
            )
            .unwrap();
        let _ = relay_to(&a, &sb, &sa.broadcast(f.change_id).unwrap());
        assert_eq!(b.file_info(f.object_id.clone()).unwrap().missing, 2);
        assert!(b.read_file(f.object_id.clone()).is_err());
        bounce(
            (&b, &sb),
            (&a, &sa),
            sb.fetch_file(f.object_id.clone()).unwrap(),
        );
        assert_eq!(b.read_file(f.object_id).unwrap(), data);
    }

    /// req: REQ-PERM-003
    #[test]
    fn subgroups_through_sessions() {
        let (a, sa, b, sb) = pair();
        // b's catch-up after joining brings it the policy.
        let catch_up = join(&a, &sa, &b, &sb);
        bounce((&b, &sb), (&a, &sa), catch_up);
        let frames = sa
            .create_subgroup("finance".into(), vec![b.device_id()])
            .unwrap();
        bounce((&a, &sa), (&b, &sb), frames);
        assert_eq!(sb.my_subgroups(), vec!["finance".to_string()]);
        assert_eq!(sa.subgroup_members("finance".into()).unwrap().len(), 2);
        let scope = format!("{}/finance", sa.org);
        let c = a
            .create_in(scope.clone(), "ledger".into(), b"x".to_vec())
            .unwrap();
        let out = relay_to(&a, &sb, &sa.broadcast(c.change_id.clone()).unwrap());
        assert!(matches!(out.event, Some(RelayEvent::Received { .. })));
        assert!(a.create_in("bad scope".into(), "x".into(), vec![]).is_err());
    }

    /// req: REQ-ENC-001
    #[test]
    fn group_membership_survives_reopen() {
        let dir = std::env::temp_dir().join(format!(
            "kith-ffi-mls-{}",
            generate_secret_key()[0..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kith.db").to_string_lossy().into_owned();
        let key = generate_secret_key();
        let org = {
            let c = KithClient::open(path.clone(), key.clone()).unwrap();
            c.create_org().unwrap()
        };
        let c = KithClient::open(path, key).unwrap();
        assert!(c.is_member(org.clone()));
        assert!(c.is_admin(org));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// req: REQ-DATA-004
    #[test]
    fn documents_merge_across_sessions() {
        let (a, sa, b, sb) = pair();
        join(&a, &sa, &b, &sb);
        let doc = a
            .create_document("todo".into(), r#"{"title":"x"}"#.into())
            .unwrap();
        let _ = relay_to(&a, &sb, &sa.broadcast(doc.change_id).unwrap());
        let ea = a
            .update_document(doc.object_id.clone(), r#"{"owner":"ann"}"#.into())
            .unwrap()
            .unwrap();
        let eb = b
            .update_document(doc.object_id.clone(), r#"{"done":true}"#.into())
            .unwrap()
            .unwrap();
        let _ = relay_to(&a, &sb, &sa.broadcast(ea.change_id).unwrap());
        let _ = relay_to(&b, &sa, &sb.broadcast(eb.change_id).unwrap());
        let want: serde_json::Value =
            serde_json::from_str(r#"{"title":"x","owner":"ann","done":true}"#).unwrap();
        for c in [&a, &b] {
            let got: serde_json::Value =
                serde_json::from_str(&c.document_json(doc.object_id.clone()).unwrap()).unwrap();
            assert_eq!(got, want);
        }
        assert!(a.create_document("todo".into(), "[]".into()).is_err());
    }

    /// req: REQ-PLAT-002
    #[test]
    fn rejects_wrong_length_secret_key() {
        assert!(KithClient::with_secret_key(vec![0; 31]).is_err());
        assert!(KithClient::with_secret_key(vec![0; 33]).is_err());
    }
}
