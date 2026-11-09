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
//! messages). [`Groups::apply_commit`] detects a competing commit for the epoch
//! just passed and decides deterministically which branch wins
//! ([`CommitOutcome::Fork`]); the losing devices get re-added (ADR 0004).

use std::collections::{BTreeMap, HashMap};

use kith_core::{DeviceId, Signer};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::SignerError;
use sha2::{Digest, Sha256};

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

/// What a verified Welcome says, for the caller's checks before joining.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeInfo {
    /// The group (org ID or `org/subgroup`).
    pub group: String,
    /// The device that added us (signed the group info).
    pub adder: Option<DeviceId>,
    /// Every device in the new group.
    pub members: Vec<DeviceId>,
    /// True if we already have state for this group (it would be replaced).
    pub replaces: bool,
}

/// What a verified commit changes, for the caller's checks before applying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitInfo {
    /// The member that made the commit.
    pub committer: DeviceId,
    /// Devices added (a re-added device is in both lists).
    pub added: Vec<DeviceId>,
    /// Devices removed.
    pub removed: Vec<DeviceId>,
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
    /// A different commit than ours moved the group out of the epoch we just left:
    /// the group forked. The winner is the commit whose committer has the lower
    /// device ID (then the lower commit hash), so every device decides the same.
    /// If `we_win` is false, this device must be re-added by a member of the
    /// winning branch; otherwise the other branch must be.
    Fork {
        /// True if our branch wins.
        we_win: bool,
        /// Who made the commit our branch followed.
        ours: DeviceId,
        /// Who made the competing commit (as claimed by the caller).
        theirs: DeviceId,
    },
}

/// A commit from the log, with the device that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedCommit {
    /// The committer (authenticated by MLS when the commit was applied).
    pub committer: DeviceId,
    /// The commit message.
    pub commit: Vec<u8>,
}

/// The last epoch change of a group: what fork detection compares against.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Transition {
    /// Epoch the group left.
    from: Epoch,
    committer: DeviceId,
    /// SHA-256 of the commit; `None` if we joined through a Welcome (no commit seen).
    hash: Option<[u8; 32]>,
}

fn commit_hash(commit: &[u8]) -> [u8; 32] {
    Sha256::digest(commit).into()
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
    commit_log: BTreeMap<String, BTreeMap<Epoch, LoggedCommit>>,
    /// Per org: the last epoch change, for fork detection.
    last: BTreeMap<String, Transition>,
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

    /// The device a KeyPackage belongs to, after checking its signature and that
    /// its credential is that device (the kith identity rule).
    pub fn key_package_device(&self, key_package: &[u8]) -> Result<DeviceId, GroupError> {
        Ok(self.validate_key_package(key_package)?.1)
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
        self.finish_add(org, from, signer.device_id(), member, &commit, &welcome)
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
        self.finish_add(
            org,
            from,
            signer.device_id(),
            member,
            &msgs.commit,
            &msgs.welcome,
        )
    }

    fn finish_add(
        &mut self,
        org: &str,
        from: Epoch,
        committer: DeviceId,
        member: DeviceId,
        commit: &MlsMessageOut,
        welcome: &MlsMessageOut,
    ) -> Result<Added, GroupError> {
        let commit = ser(commit)?;
        self.log_commit(org, from, committer, commit.clone());
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
        self.log_commit(org, from, signer.device_id(), commit.clone());
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
        self.log_commit(org, from, signer.device_id(), commit.clone());
        Ok(commit)
    }

    /// Join a group from a Welcome. Returns the org. If this device already had
    /// state for that group (re-add, REQ-ENC-004), it is replaced. Accepts any
    /// Welcome for one of our KeyPackages: callers use [`Self::join_checked`].
    pub fn join(&mut self, welcome: &[u8]) -> Result<String, GroupError> {
        self.join_checked(welcome, |_| Ok(()))
    }

    /// [`Self::join`], but only if `check` accepts what the verified Welcome says
    /// (group, adder, members). Nothing changes if it refuses.
    pub fn join_checked(
        &mut self,
        welcome: &[u8],
        check: impl FnOnce(&WelcomeInfo) -> Result<(), String>,
    ) -> Result<String, GroupError> {
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
        let adder = staged
            .welcome_sender()
            .ok()
            .and_then(|leaf| device_of(leaf.signature_key().as_slice()));
        let info = WelcomeInfo {
            group: org.clone(),
            adder,
            members: staged
                .members()
                .filter_map(|m| device_of(&m.signature_key))
                .collect(),
            replaces: self.groups.contains_key(&org),
        };
        check(&info).map_err(GroupError::Invalid)?;
        self.groups.remove(&org);
        self.commit_log.remove(&org);
        self.last.remove(&org);
        let group = staged.into_group(&self.provider).map_err(backend)?;
        if let (Some(committer), Some(from)) = (adder, group.epoch().as_u64().checked_sub(1)) {
            self.last.insert(
                org.clone(),
                Transition {
                    from,
                    committer,
                    hash: None,
                },
            );
        }
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

    /// The group (org or `org/subgroup` key) a message belongs to, read from its
    /// clear header without decrypting.
    pub fn message_group(message: &[u8]) -> Result<String, GroupError> {
        let msg = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(invalid)?
            .try_into_protocol_message()
            .map_err(invalid)?;
        String::from_utf8(msg.group_id().as_slice().to_vec())
            .map_err(|_| GroupError::Invalid("group id is not text".into()))
    }

    /// True if this device has state for group `key` (member or removed).
    pub fn has_group(&self, key: &str) -> bool {
        self.groups.contains_key(key)
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
    ///
    /// `committer` is who the commit claims to come from (the relay's sender of a
    /// broadcast, or the entry in a peer's log). It only matters for a commit we
    /// cannot apply because we already left its epoch with another commit
    /// ([`CommitOutcome::Fork`]); applied commits are attributed by MLS.
    pub fn apply_commit(
        &mut self,
        org: &str,
        commit: &[u8],
        committer: DeviceId,
    ) -> Result<CommitOutcome, GroupError> {
        self.apply_commit_checked(org, commit, committer, |_| Ok(()))
    }

    /// [`Self::apply_commit`], but a commit for our epoch is applied only if
    /// `check` accepts what it changes. Commits that propose anything but adding,
    /// removing or re-adding devices (and the committer's own key update), whose
    /// sender is not `committer`, or that bring in a leaf breaking the identity
    /// rule are refused as well. Nothing changes if it is refused.
    pub fn apply_commit_checked(
        &mut self,
        org: &str,
        commit: &[u8],
        committer: DeviceId,
        check: impl FnOnce(&CommitInfo) -> Result<(), String>,
    ) -> Result<CommitOutcome, GroupError> {
        let msg = self.protocol_message(org, commit, ContentType::Commit)?;
        let local = self.epoch(org)?;
        let got = msg.epoch().as_u64();
        if got < local {
            return Ok(self.check_fork(org, got, commit, committer));
        }
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
        .ok_or_else(|| GroupError::Invalid("committer is not a member".into()))?;
        if sender != committer {
            return Err(GroupError::Invalid("commit not from its sender".into()));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(GroupError::Invalid("not a commit".into()));
        };
        let info = commit_info(group, &staged, sender)?;
        check(&info).map_err(GroupError::Invalid)?;
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(backend)?;
        let epoch = group.epoch().as_u64();
        let removed = !group.is_active();
        self.log_commit(org, local, sender, commit.to_vec());
        Ok(CommitOutcome::Applied { epoch, removed })
    }

    /// A commit for an epoch we already left: a duplicate, or a fork if it competes
    /// with the commit we followed out of that epoch.
    fn check_fork(&self, org: &str, got: Epoch, commit: &[u8], theirs: DeviceId) -> CommitOutcome {
        let Some(last) = self.last.get(org).filter(|t| t.from == got) else {
            return CommitOutcome::Stale;
        };
        let hash = commit_hash(commit);
        if last.hash == Some(hash) {
            return CommitOutcome::Stale;
        }
        let we_win = match (last.committer.0.cmp(&theirs.0), last.hash) {
            (std::cmp::Ordering::Equal, Some(ours)) => ours < hash,
            // Joined through this committer's Welcome: its commit is the one we
            // followed; we cannot tell the two apart, so assume a duplicate.
            (std::cmp::Ordering::Equal, None) => return CommitOutcome::Stale,
            (ord, _) => ord == std::cmp::Ordering::Less,
        };
        CommitOutcome::Fork {
            we_win,
            ours: last.committer,
            theirs,
        }
    }

    /// The commit this device followed out of the previous epoch, if it has it
    /// (not when it joined through a Welcome). Sent to a peer on a losing branch so
    /// it detects the fork.
    pub fn last_commit(&self, org: &str) -> Option<LoggedCommit> {
        let last = self.last.get(org)?;
        last.hash?;
        self.commit_log.get(org)?.get(&last.from).cloned()
    }

    /// Commits from `epoch` on, oldest first, for a peer that is behind
    /// (REQ-ENC-002). `None` if the log no longer reaches back that far; the peer
    /// then needs a re-add (REQ-ENC-004).
    pub fn commits_since(
        &self,
        org: &str,
        epoch: Epoch,
    ) -> Result<Option<Vec<LoggedCommit>>, GroupError> {
        let local = self.epoch(org)?;
        if epoch >= local {
            return Ok(Some(vec![]));
        }
        let log = self.commit_log.get(org);
        let out: Vec<LoggedCommit> = (epoch..local)
            .map_while(|e| log.and_then(|l| l.get(&e)).cloned())
            .collect();
        Ok((out.len() as u64 == local - epoch).then_some(out))
    }

    fn log_commit(&mut self, org: &str, from: Epoch, committer: DeviceId, commit: Vec<u8>) {
        self.last.insert(
            org.into(),
            Transition {
                from,
                committer,
                hash: Some(commit_hash(&commit)),
            },
        );
        let log = self.commit_log.entry(org.into()).or_default();
        log.insert(from, LoggedCommit { committer, commit });
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                w.extend_from_slice(&c.committer.0);
                put_bytes(&mut w, &c.commit);
            }
        }
        put_u32(&mut w, self.last.len());
        for (org, t) in &self.last {
            put_bytes(&mut w, org.as_bytes());
            w.extend_from_slice(&t.from.to_be_bytes());
            w.extend_from_slice(&t.committer.0);
            match t.hash {
                Some(h) => {
                    w.push(1);
                    w.extend_from_slice(&h);
                }
                None => w.push(0),
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
                let epoch = r.u64()?;
                let committer = r.device()?;
                let commit = r.bytes()?.to_vec();
                log.insert(epoch, LoggedCommit { committer, commit });
            }
            commit_log.insert(org, log);
        }
        let mut last = BTreeMap::new();
        for _ in 0..r.count()? {
            let org = String::from_utf8(r.bytes()?.to_vec())
                .map_err(|_| GroupError::Corrupt("org id".into()))?;
            let from = r.u64()?;
            let committer = r.device()?;
            let hash = match r.take(1)?[0] {
                0 => None,
                1 => Some(r.array()?),
                _ => return Err(GroupError::Corrupt("transition hash flag".into())),
            };
            last.insert(
                org,
                Transition {
                    from,
                    committer,
                    hash,
                },
            );
        }
        if !r.0.is_empty() {
            return Err(GroupError::Corrupt("trailing bytes".into()));
        }
        Ok(Self {
            provider,
            groups,
            commit_log,
            last,
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

/// v2: committer per logged commit, last transition (fork detection).
const MAGIC: &[u8] = b"kith/mls-state/v2\0";

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
    /// The next `N` bytes as an array.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], GroupError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| GroupError::Corrupt("truncated".into()))
    }
    fn count(&mut self) -> Result<usize, GroupError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        // Every entry takes at least 4 bytes: a huge count fails here, not in an allocation.
        if n > self.0.len() / 4 {
            return Err(GroupError::Corrupt("count exceeds data".into()));
        }
        Ok(n)
    }
    fn u64(&mut self) -> Result<u64, GroupError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn device(&mut self) -> Result<DeviceId, GroupError> {
        Ok(DeviceId(self.array()?))
    }
    fn bytes(&mut self) -> Result<&'a [u8], GroupError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        self.take(n)
    }
}

/// The device a leaf belongs to, if it follows the kith identity rule (its
/// credential is its Ed25519 signature key, the device ID).
fn leaf_device(leaf: &LeafNode) -> Option<DeviceId> {
    let device = device_of(leaf.signature_key().as_slice())?;
    let identity = BasicCredential::try_from(leaf.credential().clone()).ok()?;
    (identity.identity() == device.0).then_some(device)
}

/// What `staged` (a commit by `sender` in `group`, not merged yet) changes.
fn commit_info(
    group: &MlsGroup,
    staged: &StagedCommit,
    sender: DeviceId,
) -> Result<CommitInfo, GroupError> {
    let bad = |m: &str| GroupError::Invalid(m.into());
    let sender_leaf = group
        .members()
        .find(|m| m.signature_key == sender.0)
        .map(|m| m.index);
    for p in staged.queued_proposals() {
        if !matches!(p.sender(), Sender::Member(l) if Some(*l) == sender_leaf) {
            return Err(bad("proposal not by the committer"));
        }
        match p.proposal().proposal_type() {
            ProposalType::Add | ProposalType::Remove => {}
            _ => return Err(bad("unsupported proposal in commit")),
        }
    }
    if let Some(leaf) = staged.update_path_leaf_node()
        && leaf_device(leaf) != Some(sender)
    {
        return Err(bad("committer changed its identity"));
    }
    let added = staged
        .add_proposals()
        .map(|a| leaf_device(a.add_proposal().key_package().leaf_node()))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| bad("added leaf breaks the identity rule"))?;
    let removed = staged
        .remove_proposals()
        .map(|r| {
            group
                .member_at(r.remove_proposal().removed())
                .and_then(|m| device_of(&m.signature_key))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| bad("removed leaf is not a member"))?;
    Ok(CommitInfo {
        committer: sender,
        added,
        removed,
    })
}

#[cfg(test)]
mod tests;
