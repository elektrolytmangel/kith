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
/// Claimed committer for commits that apply normally (only forks use it).
const ANYONE: DeviceId = DeviceId([0; 32]);

fn bytes(log: Vec<LoggedCommit>) -> Vec<Vec<u8>> {
    log.into_iter().map(|c| c.commit).collect()
}

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
    let by = devs[admin].key.device_id();
    for (i, d) in devs.iter_mut().enumerate() {
        if i != admin && i != new && d.mls.is_member(ORG) {
            d.mls.apply_commit(ORG, &added.commit, by).unwrap();
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
    assert!(devs[1].mls.apply_commit(ORG, &ct, ANYONE).is_err());
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
        let by = devs[who].key.device_id();
        devs[other].mls.apply_commit(ORG, &c, by).unwrap();
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
        devs[2].mls.apply_commit(ORG, &missed[1], ANYONE),
        Err(GroupError::EpochGap { .. })
    ));
    // Any peer serves the commits from its log.
    let logged = devs[1].mls.commits_since(ORG, e2).unwrap().unwrap();
    let commits = bytes(logged.clone());
    assert_eq!(commits, missed);
    for l in &logged {
        devs[2]
            .mls
            .apply_commit(ORG, &l.commit, l.committer)
            .unwrap();
    }
    assert_eq!(devs[2].mls.decrypt(ORG, &ct).unwrap().plaintext, b"after");
    // Replays are harmless.
    assert_eq!(
        devs[2].mls.apply_commit(ORG, &commits[0], ANYONE).unwrap(),
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
    let by = devs[1].key.device_id();
    assert_eq!(
        devs[0].mls.apply_commit(ORG, &c, by).unwrap(),
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
    let by = devs[0].key.device_id();
    for _ in 0..COMMIT_LOG_LEN + 1 {
        let c = {
            let d = &mut devs[0];
            d.mls.self_update(&d.key, ORG).unwrap()
        };
        devs[1].mls.apply_commit(ORG, &c, by).unwrap();
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
    let by = devs[1].key.device_id();
    devs[0].mls.apply_commit(ORG, &added.commit, by).unwrap();
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
    let by = devs[0].key.device_id();
    let c = {
        let d = &mut devs[0];
        d.mls.remove_member(&d.key, ORG, removed).unwrap()
    };
    devs[1].mls.apply_commit(ORG, &c, by).unwrap();
    assert!(matches!(
        devs[2].mls.apply_commit(ORG, &c, by).unwrap(),
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
fn concurrent_commits_are_detected_and_everyone_agrees_on_the_winner() {
    let mut devs = group_of(4);
    let id = |devs: &[Dev], i: usize| devs[i].key.device_id();
    // 0 and 1 rotate in the same epoch; 2 follows 0, and 3 joins through 0 later.
    let c0 = {
        let d = &mut devs[0];
        d.mls.self_update(&d.key, ORG).unwrap()
    };
    let c1 = {
        let d = &mut devs[1];
        d.mls.self_update(&d.key, ORG).unwrap()
    };
    let (id0, id1) = (id(&devs, 0), id(&devs, 1));
    devs[2].mls.apply_commit(ORG, &c0, id0).unwrap();
    let zero_wins = id0.0 < id1.0;

    let at0 = devs[0].mls.apply_commit(ORG, &c1, id1).unwrap();
    let at1 = devs[1].mls.apply_commit(ORG, &c0, id0).unwrap();
    let at2 = devs[2].mls.apply_commit(ORG, &c1, id1).unwrap();
    assert_eq!(
        at0,
        CommitOutcome::Fork {
            we_win: zero_wins,
            ours: id0,
            theirs: id1
        }
    );
    assert_eq!(
        at1,
        CommitOutcome::Fork {
            we_win: !zero_wins,
            ours: id1,
            theirs: id0
        }
    );
    assert_eq!(
        at2,
        CommitOutcome::Fork {
            we_win: zero_wins,
            ours: id0,
            theirs: id1
        }
    );
    // The same commit again is a duplicate, not a fork.
    assert_eq!(
        devs[2].mls.apply_commit(ORG, &c0, id0).unwrap(),
        CommitOutcome::Stale
    );
    // The committer can hand its commit to the other branch.
    assert_eq!(devs[0].mls.last_commit(ORG).unwrap().commit, c0);
    assert_eq!(devs[2].mls.last_commit(ORG).unwrap().committer, id0);

    // Detection survives a restart.
    devs[2].mls = Groups::from_bytes(&devs[2].mls.to_bytes()).unwrap();
    assert!(matches!(
        devs[2].mls.apply_commit(ORG, &c1, id1).unwrap(),
        CommitOutcome::Fork { .. }
    ));
}

/// req: REQ-ENC-001
#[test]
fn a_device_that_joined_by_welcome_detects_a_competing_commit() {
    let mut devs = group_of(2);
    let mut new = dev();
    let kp = new.mls.key_package(&new.key).unwrap();
    // 0 adds `new` while 1 rotates in the same epoch.
    let added = {
        let d = &mut devs[0];
        d.mls.add_member(&d.key, ORG, &kp).unwrap()
    };
    let c1 = {
        let d = &mut devs[1];
        d.mls.self_update(&d.key, ORG).unwrap()
    };
    new.mls.join(&added.welcome).unwrap();
    assert!(
        new.mls.last_commit(ORG).is_none(),
        "joined without seeing a commit"
    );
    let (id0, id1) = (devs[0].key.device_id(), devs[1].key.device_id());
    assert_eq!(
        new.mls.apply_commit(ORG, &c1, id1).unwrap(),
        CommitOutcome::Fork {
            we_win: id0.0 < id1.0,
            ours: id0,
            theirs: id1
        }
    );
    // The adder's own commit is the one it followed.
    assert_eq!(
        new.mls.apply_commit(ORG, &added.commit, id0).unwrap(),
        CommitOutcome::Stale
    );
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
        bytes(restored.commits_since(ORG, 1).unwrap().unwrap()),
        vec![added.commit]
    );

    let bytes = devs[0].mls.to_bytes();
    for len in [0, 5, bytes.len() / 2, bytes.len() - 1] {
        assert!(Groups::from_bytes(&bytes[..len]).is_err(), "len {len}");
    }
    assert!(!format!("{:?}", devs[0].mls).contains("values"));
}

/// Saved MLS state that is cut short or damaged is refused or read, never a panic.
#[test]
fn saved_state_survives_truncation_and_corruption() {
    let devs = group_of(2);
    let saved = devs[1].mls.to_bytes();
    assert!(Groups::from_bytes(&saved).is_ok());
    let step = (saved.len() / 150).max(1);
    for n in (0..saved.len()).step_by(step) {
        assert!(Groups::from_bytes(&saved[..n]).is_err(), "len {n}");
    }
    // The framing (magic and the first count) is ours. The stored values behind it
    // are authenticated by the device key before they get here (ADR 0021) and
    // parsed by openmls_memory_storage, which panics on malformed JSON, so they
    // are not corrupted here.
    for i in 0..MAGIC.len() + 4 {
        for flip in [0xffu8, 0x01, 0x80] {
            let mut m = saved.clone();
            m[i] ^= flip;
            let _ = Groups::from_bytes(&m);
        }
    }
}
