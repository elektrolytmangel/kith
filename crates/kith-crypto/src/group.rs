//! MLS group encryption (RFC 9420, REQ-ENC-001..004), backed by OpenMLS.
//!
//! One MLS group per organization: the group ID is the org ID. [`Groups`] holds
//! the MLS state of all groups a device belongs to, plus its unused KeyPackages
//! and a recent commit log per group (REQ-ENC-002), and can be saved as one blob
//! ([`Groups::to_bytes`] / [`Groups::from_bytes`]).
//!
//! Ciphersuite: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` with the
//! pure-Rust RustCrypto provider (ADR 0004). The device's Ed25519 key is its MLS
//! signature key and its credential, so the MLS sender of a message is a
//! [`DeviceId`]. All messages, commits included, are MLS `PrivateMessage`s; the
//! relay sees only group ID, epoch and content type.
//!
//! Sans-IO: every operation returns the bytes to send; nothing here does I/O.
//! Commits are merged locally as soon as they are created. Two members
//! committing in the same epoch fork the group (the relay does not order
//! messages); see ADR 0004 for why that is accepted for now.

use std::collections::{BTreeMap, HashMap};

use kith_core::{DeviceId, Signer};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::SignerError;

/// MLS epoch number.
pub type Epoch = u64;

/// The one ciphersuite kith uses (ADR 0004).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// How many past epochs' keys are kept to decrypt late messages. Trades a little
/// forward secrecy for tolerating messages that cross a commit in flight.
const MAX_PAST_EPOCHS: usize = 3;

/// How many recent commits are kept per group for peers that missed them.
pub const COMMIT_LOG_LEN: usize = 256;

/// Errors from group operations.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    /// A message arrived for an epoch we have not reached (missed commits).
    #[error("missing commits: local epoch {local}, message for {got}")]
    EpochGap {
        /// Our epoch.
        local: Epoch,
        /// Epoch of the message.
        got: Epoch,
    },
    /// This device is not (or no longer) a member of the group.
    #[error("not a member of group {0:?}")]
    NotMember(String),
    /// The group already exists on this device.
    #[error("group {0:?} already exists")]
    AlreadyExists(String),
    /// The device to add is already a member (use [`Groups::readd_member`]).
    #[error("device is already a member")]
    AlreadyMember,
    /// The device is not in the group.
    #[error("device is not in the group")]
    UnknownMember,
    /// The message is malformed, for another group, of the wrong kind, or fails
    /// to decrypt or authenticate.
    #[error("invalid MLS message: {0}")]
    Invalid(String),
    /// Saved state could not be read.
    #[error("corrupt MLS state: {0}")]
    Corrupt(String),
    /// Error inside OpenMLS.
    #[error("mls: {0}")]
    Backend(String),
}

fn backend(e: impl std::fmt::Debug) -> GroupError {
    GroupError::Backend(format!("{e:?}"))
}

fn invalid(e: impl std::fmt::Debug) -> GroupError {
    GroupError::Invalid(format!("{e:?}"))
}

/// Result of [`Groups::add_member`] / [`Groups::readd_member`].
#[derive(Debug)]
pub struct Added {
    /// The added device.
    pub member: DeviceId,
    /// Commit to broadcast to the existing members.
    pub commit: Vec<u8>,
    /// Welcome to send directly to the new member.
    pub welcome: Vec<u8>,
}

/// Result of [`Groups::apply_commit`].
#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Applied; the group is now at `epoch`.
    Applied {
        /// New epoch.
        epoch: Epoch,
        /// True if the commit removed this device from the group.
        removed: bool,
    },
    /// The commit is for an epoch we already passed (duplicate or our own).
    Stale,
}

/// A decrypted application message.
#[derive(Debug)]
pub struct Decrypted {
    /// MLS sender (authenticated by the group, not by the relay).
    pub sender: DeviceId,
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

/// OpenMLS provider: RustCrypto for crypto and randomness, in-memory storage
/// that [`Groups`] serializes as a whole.
#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

/// Lets any kith [`Signer`] (in-memory key, keychain, secure enclave) sign MLS
/// messages. MLS signatures are domain-separated by RFC 9420 labels, so they can
/// never be confused with kith change or relay-auth signatures.
struct MlsSigner<'a>(&'a dyn Signer);

impl openmls_traits::signatures::Signer for MlsSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_vec())
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn credential(device: DeviceId) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(device.0.to_vec()).into(),
        signature_key: device.0.to_vec().into(),
    }
}

fn device_of(signature_key: &[u8]) -> Option<DeviceId> {
    signature_key.try_into().ok().map(DeviceId)
}

fn group_id(org: &str) -> GroupId {
    GroupId::from_slice(org.as_bytes())
}

fn ser(msg: &MlsMessageOut) -> Result<Vec<u8>, GroupError> {
    msg.tls_serialize_detached().map_err(backend)
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

/// A device's MLS state for all its groups.
#[derive(Default)]
pub struct Groups {
    provider: Provider,
    groups: HashMap<String, MlsGroup>,
    /// Per org: commit that moved the group *from* epoch `k` to `k + 1`.
    commit_log: BTreeMap<String, BTreeMap<Epoch, Vec<u8>>>,
}

impl std::fmt::Debug for Groups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("Groups")
            .field("groups", &self.groups.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Groups {
    /// Empty state (no groups, no KeyPackages).
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh KeyPackage for this device, to send to an admin who adds it to a
    /// group. The private part stays in this state until a Welcome uses it, so
    /// save the state ([`Self::to_bytes`]) before sending the KeyPackage.
    pub fn key_package(&mut self, signer: &dyn Signer) -> Result<Vec<u8>, GroupError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &MlsSigner(signer),
                credential(signer.device_id()),
            )
            .map_err(backend)?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(backend)
    }

    /// Create the group for `org` with this device as the only member (the
    /// creator; it becomes the first admin in phase 5).
    pub fn create_group(&mut self, signer: &dyn Signer, org: &str) -> Result<(), GroupError> {
        if self.groups.contains_key(org) {
            return Err(GroupError::AlreadyExists(org.into()));
        }
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &MlsSigner(signer),
            &create_config(),
            group_id(org),
            credential(signer.device_id()),
        )
        .map_err(backend)?;
        self.groups.insert(org.into(), group);
        Ok(())
    }

    /// Orgs this device has a group for.
    pub fn orgs(&self) -> Vec<String> {
        let mut v: Vec<String> = self.groups.keys().cloned().collect();
        v.sort();
        v
    }

    /// True if this device is an active member of `org`'s group.
    pub fn is_member(&self, org: &str) -> bool {
        self.groups.get(org).is_some_and(|g| g.is_active())
    }

    /// Current epoch of `org`'s group.
    pub fn epoch(&self, org: &str) -> Result<Epoch, GroupError> {
        Ok(self.group(org)?.epoch().as_u64())
    }

    /// Devices in `org`'s group.
    pub fn members(&self, org: &str) -> Result<Vec<DeviceId>, GroupError> {
        Ok(self
            .group(org)?
            .members()
            .filter_map(|m| device_of(&m.signature_key))
            .collect())
    }

    /// Validate a KeyPackage and add its device to `org`'s group. Broadcast
    /// `commit` to the group and send `welcome` to the new device.
    pub fn add_member(
        &mut self,
        signer: &dyn Signer,
        org: &str,
        key_package: &[u8],
    ) -> Result<Added, GroupError> {
        let (kp, member) = self.validate_key_package(key_package)?;
        if self.leaf_of(org, member)?.is_some() {
            return Err(GroupError::AlreadyMember);
        }
        let from = self.epoch(org)?;
        let group = group_mut(&mut self.groups, org)?;
        let (commit, welcome, _) = group
            .add_members(&self.provider, &MlsSigner(signer), &[kp])
            .map_err(backend)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(backend)?;
        self.finish_add(org, from, member, &commit, &welcome)
    }

    /// Re-add a device that is already a member but lost the group, for example
    /// because it fell further behind than the commit log reaches (REQ-ENC-004):
    /// its old leaf is replaced by the new KeyPackage in one commit.
    pub fn readd_member(
        &mut self,
        signer: &dyn Signer,
        org: &str,
        key_package: &[u8],
    ) -> Result<Added, GroupError> {
        let (kp, member) = self.validate_key_package(key_package)?;
        let leaf = self
            .leaf_of(org, member)?
            .ok_or(GroupError::UnknownMember)?;
        let from = self.epoch(org)?;
        let group = group_mut(&mut self.groups, org)?;
        let msgs = group
            .swap_members(&self.provider, &MlsSigner(signer), &[leaf], &[kp])
            .map_err(backend)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(backend)?;
        self.finish_add(org, from, member, &msgs.commit, &msgs.welcome)
    }

    fn finish_add(
        &mut self,
        org: &str,
        from: Epoch,
        member: DeviceId,
        commit: &MlsMessageOut,
        welcome: &MlsMessageOut,
    ) -> Result<Added, GroupError> {
        let commit = ser(commit)?;
        self.log_commit(org, from, commit.clone());
        Ok(Added {
            member,
            commit,
            welcome: ser(welcome)?,
        })
    }

    /// Remove a device from `org`'s group. Broadcast the returned commit; the
    /// removed device can no longer decrypt anything sent after it.
    pub fn remove_member(
        &mut self,
        signer: &dyn Signer,
        org: &str,
        device: DeviceId,
    ) -> Result<Vec<u8>, GroupError> {
        let leaf = self
            .leaf_of(org, device)?
            .ok_or(GroupError::UnknownMember)?;
        let from = self.epoch(org)?;
        let group = group_mut(&mut self.groups, org)?;
        let (commit, _, _) = group
            .remove_members(&self.provider, &MlsSigner(signer), &[leaf])
            .map_err(backend)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(backend)?;
        let commit = ser(&commit)?;
        self.log_commit(org, from, commit.clone());
        Ok(commit)
    }

    /// Rotate this device's own leaf key (MLS update, REQ-ENC-003). Broadcast the
    /// returned commit.
    pub fn self_update(&mut self, signer: &dyn Signer, org: &str) -> Result<Vec<u8>, GroupError> {
        let from = self.epoch(org)?;
        let group = group_mut(&mut self.groups, org)?;
        let bundle = group
            .self_update(
                &self.provider,
                &MlsSigner(signer),
                LeafNodeParameters::default(),
            )
            .map_err(backend)?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(backend)?;
        let commit = ser(bundle.commit())?;
        self.log_commit(org, from, commit.clone());
        Ok(commit)
    }

    /// Join a group from a Welcome. Returns the org. If this device already had
    /// state for that group (re-add, REQ-ENC-004), it is replaced.
    pub fn join(&mut self, welcome: &[u8]) -> Result<String, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome).map_err(invalid)?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(GroupError::Invalid("not a welcome".into()));
        };
        // Only replaces the old group once the Welcome decrypted with our
        // KeyPackage and verified.
        let staged = StagedWelcome::build_from_welcome(&self.provider, &join_config(), welcome)
            .map_err(invalid)?
            .replace_old_group()
            .build()
            .map_err(invalid)?;
        let org = String::from_utf8(staged.group_context().group_id().as_slice().to_vec())
            .map_err(|_| GroupError::Invalid("group id is not an org id".into()))?;
        self.groups.remove(&org);
        self.commit_log.remove(&org);
        let group = staged.into_group(&self.provider).map_err(backend)?;
        self.groups.insert(org.clone(), group);
        Ok(org)
    }

    /// Encrypt an application message for `org`'s group.
    pub fn encrypt(
        &mut self,
        signer: &dyn Signer,
        org: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, GroupError> {
        let group = group_mut(&mut self.groups, org)?;
        if !group.is_active() {
            return Err(GroupError::NotMember(org.into()));
        }
        let msg = group
            .create_message(&self.provider, &MlsSigner(signer), plaintext)
            .map_err(backend)?;
        ser(&msg)
    }

    /// The epoch a message (application or commit) was sent in, read from its
    /// clear header without decrypting.
    pub fn message_epoch(message: &[u8]) -> Result<Epoch, GroupError> {
        Ok(MlsMessageIn::tls_deserialize_exact(message)
            .map_err(invalid)?
            .try_into_protocol_message()
            .map_err(invalid)?
            .epoch()
            .as_u64())
    }

    /// Decrypt an application message for `org`'s group.
    pub fn decrypt(&mut self, org: &str, message: &[u8]) -> Result<Decrypted, GroupError> {
        let msg = self.protocol_message(org, message, ContentType::Application)?;
        let local = self.epoch(org)?;
        let got = msg.epoch().as_u64();
        if got > local {
            return Err(GroupError::EpochGap { local, got });
        }
        let group = group_mut(&mut self.groups, org)?;
        let processed = group
            .process_message(&self.provider, msg)
            .map_err(invalid)?;
        let sender = match processed.sender() {
            Sender::Member(leaf) => group
                .member_at(*leaf)
                .and_then(|m| device_of(&m.signature_key)),
            _ => None,
        }
        .ok_or_else(|| GroupError::Invalid("sender is not a member".into()))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Decrypted {
                sender,
                plaintext: app.into_bytes(),
            }),
            _ => Err(GroupError::Invalid("not an application message".into())),
        }
    }

    /// Apply a commit received from another member. Commits must be applied in
    /// epoch order: a commit for a later epoch returns [`GroupError::EpochGap`]
    /// (fetch the missing ones from a peer's [`Self::commits_since`]).
    pub fn apply_commit(&mut self, org: &str, commit: &[u8]) -> Result<CommitOutcome, GroupError> {
        let msg = self.protocol_message(org, commit, ContentType::Commit)?;
        let local = self.epoch(org)?;
        let got = msg.epoch().as_u64();
        if got < local {
            return Ok(CommitOutcome::Stale);
        }
        if got > local {
            return Err(GroupError::EpochGap { local, got });
        }
        let group = group_mut(&mut self.groups, org)?;
        let processed = group
            .process_message(&self.provider, msg)
            .map_err(invalid)?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(GroupError::Invalid("not a commit".into()));
        };
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(backend)?;
        let epoch = group.epoch().as_u64();
        let removed = !group.is_active();
        self.log_commit(org, local, commit.to_vec());
        Ok(CommitOutcome::Applied { epoch, removed })
    }

    /// Commits from `epoch` on, oldest first, for a peer that is behind
    /// (REQ-ENC-002). `None` if the log no longer reaches back that far; the peer
    /// then needs a re-add (REQ-ENC-004).
    pub fn commits_since(
        &self,
        org: &str,
        epoch: Epoch,
    ) -> Result<Option<Vec<Vec<u8>>>, GroupError> {
        let local = self.epoch(org)?;
        if epoch >= local {
            return Ok(Some(vec![]));
        }
        let log = self.commit_log.get(org);
        let out: Vec<Vec<u8>> = (epoch..local)
            .map_while(|e| log.and_then(|l| l.get(&e)).cloned())
            .collect();
        Ok((out.len() as u64 == local - epoch).then_some(out))
    }

    fn log_commit(&mut self, org: &str, from: Epoch, commit: Vec<u8>) {
        let log = self.commit_log.entry(org.into()).or_default();
        log.insert(from, commit);
        while log.len() > COMMIT_LOG_LEN {
            log.pop_first();
        }
    }

    fn protocol_message(
        &self,
        org: &str,
        bytes: &[u8],
        want: ContentType,
    ) -> Result<ProtocolMessage, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(invalid)?
            .try_into_protocol_message()
            .map_err(invalid)?;
        if msg.group_id() != &group_id(org) {
            return Err(GroupError::Invalid("message is for another group".into()));
        }
        if msg.content_type() != want {
            return Err(GroupError::Invalid(format!(
                "expected {want:?}, got {:?}",
                msg.content_type()
            )));
        }
        Ok(msg)
    }

    fn validate_key_package(&self, bytes: &[u8]) -> Result<(KeyPackage, DeviceId), GroupError> {
        let kp = KeyPackageIn::tls_deserialize_exact(bytes)
            .map_err(invalid)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(invalid)?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(GroupError::Invalid("wrong ciphersuite".into()));
        }
        // kith identity rule: the credential is the device ID, which is the
        // signature key. Anything else could impersonate another device.
        let leaf = kp.leaf_node();
        let device = device_of(leaf.signature_key().as_slice())
            .ok_or_else(|| GroupError::Invalid("signature key is not Ed25519".into()))?;
        let identity = BasicCredential::try_from(leaf.credential().clone()).map_err(invalid)?;
        if identity.identity() != device.0 {
            return Err(GroupError::Invalid(
                "credential does not match the signature key".into(),
            ));
        }
        Ok((kp, device))
    }

    fn leaf_of(&self, org: &str, device: DeviceId) -> Result<Option<LeafNodeIndex>, GroupError> {
        Ok(self
            .group(org)?
            .members()
            .find(|m| m.signature_key == device.0)
            .map(|m| m.index))
    }

    fn group(&self, org: &str) -> Result<&MlsGroup, GroupError> {
        self.groups
            .get(org)
            .ok_or_else(|| GroupError::NotMember(org.into()))
    }

    // ---- persistence ----

    /// Serialize the whole state (group secrets, unused KeyPackage private keys,
    /// commit logs). **Contains secrets**: store it like the device key.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(MAGIC);
        let values = self
            .provider
            .storage
            .values
            .read()
            .expect("storage lock poisoned");
        let mut entries: Vec<_> = values.iter().collect();
        entries.sort();
        put_u32(&mut w, entries.len());
        for (k, v) in entries {
            put_bytes(&mut w, k);
            put_bytes(&mut w, v);
        }
        put_u32(&mut w, self.groups.len());
        for org in self.orgs() {
            put_bytes(&mut w, org.as_bytes());
        }
        put_u32(&mut w, self.commit_log.len());
        for (org, log) in &self.commit_log {
            put_bytes(&mut w, org.as_bytes());
            put_u32(&mut w, log.len());
            for (epoch, c) in log {
                w.extend_from_slice(&epoch.to_be_bytes());
                put_bytes(&mut w, c);
            }
        }
        w
    }

    /// Restore state saved with [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupError> {
        let mut r = Reader(bytes);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(GroupError::Corrupt("unknown format".into()));
        }
        let mut values = HashMap::new();
        for _ in 0..r.count()? {
            let k = r.bytes()?.to_vec();
            values.insert(k, r.bytes()?.to_vec());
        }
        let provider = Provider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: values.into(),
            },
        };
        let mut groups = HashMap::new();
        for _ in 0..r.count()? {
            let org = String::from_utf8(r.bytes()?.to_vec())
                .map_err(|_| GroupError::Corrupt("org id".into()))?;
            let group = MlsGroup::load(provider.storage(), &group_id(&org))
                .map_err(|e| GroupError::Corrupt(format!("{e:?}")))?
                .ok_or_else(|| GroupError::Corrupt(format!("group {org:?} missing")))?;
            groups.insert(org, group);
        }
        let mut commit_log = BTreeMap::new();
        for _ in 0..r.count()? {
            let org = String::from_utf8(r.bytes()?.to_vec())
                .map_err(|_| GroupError::Corrupt("org id".into()))?;
            let mut log = BTreeMap::new();
            for _ in 0..r.count()? {
                let epoch = u64::from_be_bytes(r.take(8)?.try_into().expect("8 bytes"));
                log.insert(epoch, r.bytes()?.to_vec());
            }
            commit_log.insert(org, log);
        }
        if !r.0.is_empty() {
            return Err(GroupError::Corrupt("trailing bytes".into()));
        }
        Ok(Self {
            provider,
            groups,
            commit_log,
        })
    }
}

fn group_mut<'a>(
    groups: &'a mut HashMap<String, MlsGroup>,
    org: &str,
) -> Result<&'a mut MlsGroup, GroupError> {
    groups
        .get_mut(org)
        .ok_or_else(|| GroupError::NotMember(org.into()))
}

const MAGIC: &[u8] = b"kith/mls-state/v1\0";

fn put_u32(w: &mut Vec<u8>, n: usize) {
    w.extend_from_slice(&(n as u32).to_be_bytes());
}

fn put_bytes(w: &mut Vec<u8>, b: &[u8]) {
    put_u32(w, b.len());
    w.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], GroupError> {
        if self.0.len() < n {
            return Err(GroupError::Corrupt("truncated".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn count(&mut self) -> Result<usize, GroupError> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        // Every entry takes at least 4 bytes: a huge count fails here, not in an allocation.
        if n > self.0.len() / 4 {
            return Err(GroupError::Corrupt("count exceeds data".into()));
        }
        Ok(n)
    }
    fn bytes(&mut self) -> Result<&'a [u8], GroupError> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKey;

    struct Dev {
        key: DeviceKey,
        mls: Groups,
    }

    fn dev() -> Dev {
        Dev {
            key: DeviceKey::generate(),
            mls: Groups::new(),
        }
    }

    const ORG: &str = "org-1";

    /// `admin` creates the group; every other device joins through a Welcome.
    fn group_of(n: usize) -> Vec<Dev> {
        let mut devs: Vec<Dev> = (0..n).map(|_| dev()).collect();
        let d = &mut devs[0];
        d.mls.create_group(&d.key, ORG).unwrap();
        for i in 1..n {
            add(&mut devs, 0, i);
        }
        devs
    }

    /// `admin` adds `new`; all existing members apply the commit.
    fn add(devs: &mut [Dev], admin: usize, new: usize) {
        let kp = {
            let d = &mut devs[new];
            d.mls.key_package(&d.key).unwrap()
        };
        let added = {
            let a = &mut devs[admin];
            a.mls.add_member(&a.key, ORG, &kp).unwrap()
        };
        assert_eq!(added.member, devs[new].key.device_id());
        for (i, d) in devs.iter_mut().enumerate() {
            if i != admin && i != new && d.mls.is_member(ORG) {
                d.mls.apply_commit(ORG, &added.commit).unwrap();
            }
        }
        assert_eq!(devs[new].mls.join(&added.welcome).unwrap(), ORG);
    }

    fn send(devs: &mut [Dev], from: usize, msg: &[u8]) -> Vec<u8> {
        let d = &mut devs[from];
        d.mls.encrypt(&d.key, ORG, msg).unwrap()
    }

    /// req: REQ-ENC-001
    #[test]
    fn members_exchange_encrypted_messages() {
        let mut devs = group_of(3);
        let ct = send(&mut devs, 1, b"hello");
        assert!(!ct.windows(5).any(|w| w == b"hello"), "plaintext leaked");
        for i in [0, 2] {
            let got = devs[i].mls.decrypt(ORG, &ct).unwrap();
            assert_eq!(got.plaintext, b"hello");
            assert_eq!(got.sender, devs[1].key.device_id());
        }
        let mut members = devs[2].mls.members(ORG).unwrap();
        let mut want: Vec<_> = devs.iter().map(|d| d.key.device_id()).collect();
        members.sort_by_key(|d| d.0);
        want.sort_by_key(|d| d.0);
        assert_eq!(members, want);
        assert!(devs.iter().all(|d| d.mls.epoch(ORG).unwrap() == 2));
    }

    /// req: REQ-ENC-001
    #[test]
    fn outsiders_and_tampering_fail() {
        let mut devs = group_of(2);
        let ct = send(&mut devs, 0, b"secret");
        // A device with its own group of the same id cannot read it.
        let mut outsider = dev();
        outsider.mls.create_group(&outsider.key, ORG).unwrap();
        assert!(outsider.mls.decrypt(ORG, &ct).is_err());
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(devs[1].mls.decrypt(ORG, &bad).is_err());
        assert!(devs[1].mls.decrypt("other-org", &ct).is_err());
        assert!(devs[1].mls.decrypt(ORG, b"garbage").is_err());
        // An application message is not a commit, and vice versa.
        assert!(devs[1].mls.apply_commit(ORG, &ct).is_err());
        assert_eq!(devs[1].mls.decrypt(ORG, &ct).unwrap().plaintext, b"secret");
    }

    #[test]
    fn key_package_must_bind_device_id() {
        let mut admin = dev();
        admin.mls.create_group(&admin.key, ORG).unwrap();
        assert!(admin.mls.add_member(&admin.key, ORG, b"nope").is_err());
        let mut new = dev();
        let kp = new.mls.key_package(&new.key).unwrap();
        admin.mls.add_member(&admin.key, ORG, &kp).unwrap();
        let kp2 = new.mls.key_package(&new.key).unwrap();
        assert!(matches!(
            admin.mls.add_member(&admin.key, ORG, &kp2),
            Err(GroupError::AlreadyMember)
        ));
    }

    /// req: REQ-ENC-002
    #[test]
    fn missed_commits_are_detected_and_caught_up_from_the_log() {
        let mut devs = group_of(3);
        // Device 2 goes offline; 0 rotates twice and 1 once.
        let mut missed = vec![];
        for who in [0, 1, 0] {
            let c = {
                let d = &mut devs[who];
                d.mls.self_update(&d.key, ORG).unwrap()
            };
            let other = 1 - who;
            devs[other].mls.apply_commit(ORG, &c).unwrap();
            missed.push(c);
        }
        let ct = send(&mut devs, 0, b"after");
        let e2 = devs[2].mls.epoch(ORG).unwrap();
        assert!(matches!(
            devs[2].mls.decrypt(ORG, &ct),
            Err(GroupError::EpochGap { local, got }) if local == e2 && got == e2 + 3
        ));
        // Applying a later commit first is refused: order matters.
        assert!(matches!(
            devs[2].mls.apply_commit(ORG, &missed[1]),
            Err(GroupError::EpochGap { .. })
        ));
        // Any peer serves the commits from its log.
        let commits = devs[1].mls.commits_since(ORG, e2).unwrap().unwrap();
        assert_eq!(commits, missed);
        for c in &commits {
            devs[2].mls.apply_commit(ORG, c).unwrap();
        }
        assert_eq!(devs[2].mls.decrypt(ORG, &ct).unwrap().plaintext, b"after");
        // Replays are harmless.
        assert_eq!(
            devs[2].mls.apply_commit(ORG, &commits[0]).unwrap(),
            CommitOutcome::Stale
        );
        assert_eq!(devs[1].mls.commits_since(ORG, 99).unwrap(), Some(vec![]));
    }

    /// req: REQ-ENC-003
    #[test]
    fn self_update_rotates_keys() {
        let mut devs = group_of(2);
        let before = devs[1].mls.epoch(ORG).unwrap();
        let c = {
            let d = &mut devs[1];
            d.mls.self_update(&d.key, ORG).unwrap()
        };
        assert_eq!(
            devs[0].mls.apply_commit(ORG, &c).unwrap(),
            CommitOutcome::Applied {
                epoch: before + 1,
                removed: false
            }
        );
        let ct = send(&mut devs, 1, b"x");
        assert_eq!(devs[0].mls.decrypt(ORG, &ct).unwrap().plaintext, b"x");
    }

    /// req: REQ-ENC-004
    #[test]
    fn device_beyond_the_log_is_readded() {
        let mut devs = group_of(3);
        for _ in 0..COMMIT_LOG_LEN + 1 {
            let c = {
                let d = &mut devs[0];
                d.mls.self_update(&d.key, ORG).unwrap()
            };
            devs[1].mls.apply_commit(ORG, &c).unwrap();
        }
        let e2 = devs[2].mls.epoch(ORG).unwrap();
        assert_eq!(devs[0].mls.commits_since(ORG, e2).unwrap(), None);
        // Device 2 sends a fresh KeyPackage; an online member swaps its leaf.
        let kp = {
            let d = &mut devs[2];
            d.mls.key_package(&d.key).unwrap()
        };
        let added = {
            let d = &mut devs[1];
            d.mls.readd_member(&d.key, ORG, &kp).unwrap()
        };
        devs[0].mls.apply_commit(ORG, &added.commit).unwrap();
        devs[2].mls.join(&added.welcome).unwrap();
        assert_eq!(devs[2].mls.members(ORG).unwrap().len(), 3);
        let ct = send(&mut devs, 0, b"back");
        assert_eq!(devs[2].mls.decrypt(ORG, &ct).unwrap().plaintext, b"back");
        // Re-adding an unknown device is refused.
        let mut stranger = dev();
        let kp = stranger.mls.key_package(&stranger.key).unwrap();
        let d = &mut devs[0];
        assert!(matches!(
            d.mls.readd_member(&d.key, ORG, &kp),
            Err(GroupError::UnknownMember)
        ));
    }

    /// req: REQ-ENC-001
    #[test]
    fn removed_device_cannot_read_new_messages() {
        let mut devs = group_of(3);
        let removed = devs[2].key.device_id();
        let c = {
            let d = &mut devs[0];
            d.mls.remove_member(&d.key, ORG, removed).unwrap()
        };
        devs[1].mls.apply_commit(ORG, &c).unwrap();
        assert!(matches!(
            devs[2].mls.apply_commit(ORG, &c).unwrap(),
            CommitOutcome::Applied { removed: true, .. }
        ));
        assert!(!devs[2].mls.is_member(ORG));
        let ct = send(&mut devs, 0, b"after removal");
        assert!(devs[2].mls.decrypt(ORG, &ct).is_err());
        assert_eq!(
            devs[1].mls.decrypt(ORG, &ct).unwrap().plaintext,
            b"after removal"
        );
        let d = &mut devs[2];
        assert!(d.mls.encrypt(&d.key, ORG, b"x").is_err());
    }

    /// req: REQ-ENC-001
    #[test]
    fn state_survives_save_and_restore() {
        let mut devs = group_of(2);
        // A pending KeyPackage must survive too: the Welcome may arrive after a restart.
        let mut new = dev();
        let kp = new.mls.key_package(&new.key).unwrap();
        new.mls = Groups::from_bytes(&new.mls.to_bytes()).unwrap();

        devs[1].mls = Groups::from_bytes(&devs[1].mls.to_bytes()).unwrap();
        let ct = send(&mut devs, 0, b"persisted");
        assert_eq!(
            devs[1].mls.decrypt(ORG, &ct).unwrap().plaintext,
            b"persisted"
        );
        let ct = send(&mut devs, 1, b"and back");
        assert_eq!(
            devs[0].mls.decrypt(ORG, &ct).unwrap().plaintext,
            b"and back"
        );

        let added = {
            let d = &mut devs[1];
            d.mls.add_member(&d.key, ORG, &kp).unwrap()
        };
        new.mls.join(&added.welcome).unwrap();
        let restored = Groups::from_bytes(&devs[1].mls.to_bytes()).unwrap();
        assert_eq!(
            restored.commits_since(ORG, 1).unwrap().unwrap(),
            vec![added.commit]
        );

        let bytes = devs[0].mls.to_bytes();
        for len in [0, 5, bytes.len() / 2, bytes.len() - 1] {
            assert!(Groups::from_bytes(&bytes[..len]).is_err(), "len {len}");
        }
        assert!(!format!("{:?}", devs[0].mls).contains("values"));
    }
}
