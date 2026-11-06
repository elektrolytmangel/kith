use std::time::Duration;

use kith_client::{MemoryStore, ObjectType, Store as _};
use kith_relay_server::{app, new_state};
use tokio::time::timeout;

use super::*;

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app(new_state(Duration::from_secs(10))))
            .await
            .unwrap();
    });
    url
}

fn temp_dir(name: &str) -> PathBuf {
    let r: [u8; 8] = kith_client::DeviceKey::generate().secret_bytes()[..8]
        .try_into()
        .unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    std::env::temp_dir().join(format!("kith-always-on-{name}-{hex}"))
}

async fn until<S: kith_client::Store, T>(
    l: &mut LiveClient<S>,
    mut pick: impl FnMut(Event) -> Option<T>,
) -> T {
    loop {
        let ev = timeout(Duration::from_secs(10), l.next_event())
            .await
            .expect("timed out")
            .unwrap()
            .expect("connection closed");
        if let Some(t) = pick(ev) {
            return t;
        }
    }
}

/// The admin accepts the next valid claim.
/// Accept the next claim; returns the device and the code the admin was shown.
async fn accept_one(admin: &mut LiveClient<MemoryStore>) -> (String, String) {
    let (from, code) = until(admin, |e| match e {
        Event::InviteClaimed { from, code, .. } => Some((from, code)),
        _ => None,
    })
    .await;
    admin.accept_claim(&from).await.unwrap();
    (from, code)
}

/// req: REQ-SYNC-006
/// req: REQ-SYNC-001
/// req: REQ-ENC-003
#[tokio::test]
async fn the_always_on_client_is_the_preferred_peer_and_serves_when_others_are_offline() {
    let url = relay().await;
    let mut founder = Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap();
    let org = founder.create_org().unwrap();
    let link_x = founder.create_invite(&org, &url, 60_000).unwrap();
    let link_b = founder.create_invite(&org, &url, 60_000).unwrap();
    let mut admin = LiveClient::connect(&url, &org, founder).await.unwrap();
    // Claims reach the admins the relay has registered: wait until it has this one.
    until(&mut admin, |e| {
        matches!(e, Event::Presence { .. }).then_some(())
    })
    .await;

    // The always-on client joins by invite, then runs in the background.
    let dir = temp_dir("x");
    let x_id = device_id(&dir).unwrap();
    let join_dir = dir.clone();
    let shown = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let shown_by_x = shown.clone();
    let joining = tokio::spawn(async move {
        join(&join_dir, &link_x, Duration::from_secs(10), move |code| {
            *shown_by_x.lock().unwrap() = Some(code.to_string())
        })
        .await
    });
    let (_, admin_code) = accept_one(&mut admin).await;
    assert_eq!(joining.await.unwrap().unwrap(), org);
    assert_eq!(
        shown.lock().unwrap().as_deref(),
        Some(admin_code.as_str()),
        "both show the same code"
    );
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let options = Options {
        catch_up_every: Duration::from_secs(3600),
        rotate_every: Duration::from_secs(3600),
        max_backoff: Duration::from_millis(200),
    };
    let run_dir = dir.clone();
    let running = tokio::spawn(async move {
        run(&run_dir, options, async {
            let _ = stopped.await;
        })
        .await
    });
    // It comes online and rotates its key on start (no rotation recorded yet).
    until(&mut admin, |e| match e {
        Event::Presence { online, .. } if online.contains(&x_id) => Some(()),
        _ => None,
    })
    .await;
    until(&mut admin, |e| {
        matches!(e, Event::GroupChanged { .. }).then_some(())
    })
    .await;
    assert!(dir.join("rotated").exists());

    // A new member joins; with the admin and the always-on client online, the relay
    // hands its catch-up to the always-on client.
    let mut b = LiveClient::connect(
        &url,
        &org,
        Client::new(DeviceKey::generate(), MemoryStore::new()).unwrap(),
    )
    .await
    .unwrap();
    b.claim(&link_b).await.unwrap();
    accept_one(&mut admin).await;
    let served_by = until(&mut b, |e| match e {
        Event::SyncCompared { from, .. } => Some(from),
        _ => None,
    })
    .await;
    assert_eq!(served_by, x_id, "the relay prefers the always-on client");
    let b_client = b.into_client().await;

    // The admin writes while b is offline, makes sure the always-on client has it,
    // then goes offline too.
    let note = admin
        .create(
            ObjectType::new("note"),
            b"written while b was away".to_vec(),
        )
        .await
        .unwrap();
    until(&mut admin, |e| match e {
        Event::Receipt { delivered } if delivered.contains(&x_id) => Some(()),
        _ => None,
    })
    .await;
    let _ = admin.into_client().await;

    // b comes back: only the always-on client is online, and it has the note.
    // (Late answers from b's previous session can arrive first: the relay routes
    // directs to a device's current connection.)
    let mut b = LiveClient::connect(&url, &org, b_client).await.unwrap();
    b.catch_up().await.unwrap();
    timeout(Duration::from_secs(10), async {
        while !b.client().store().contains(&note.change_id).unwrap() {
            b.next_event().await.unwrap().expect("connection closed");
        }
    })
    .await
    .expect("b did not get the note from the always-on client");
    assert_eq!(b.client().history(&note.body.object_id).unwrap().len(), 1);

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn running_without_joining_is_a_clear_error() {
    let dir = temp_dir("empty");
    let err = run(&dir, Options::default(), std::future::pending())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("join first"), "{err}");
    let _ = std::fs::remove_dir_all(dir);
}

/// req: REQ-DATA-006
#[test]
fn backups_restore_a_data_directory() {
    let dir = temp_dir("bk");
    let mut c = open_client(&dir).unwrap();
    let org = c.create_org().unwrap();
    let note = c.create(ObjectType::new("note"), b"kept".to_vec()).unwrap();
    drop(c);
    let backup = export_backup(&dir, "pw").unwrap();
    let other = temp_dir("restored");
    assert!(restore_backup(&other, &backup, "wrong", "ws://r").is_err());
    assert_eq!(
        restore_backup(&other, &backup, "pw", "ws://r").unwrap(),
        org
    );
    assert!(
        restore_backup(&other, &backup, "pw", "ws://r").is_err(),
        "not over an existing device"
    );
    let restored = open_client(&other).unwrap();
    assert!(restored.store().contains(&note.change_id).unwrap());
    assert_eq!(device_id(&other).unwrap(), device_id(&dir).unwrap());
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(other);
}
