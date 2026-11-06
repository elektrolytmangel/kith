//! The always-on client (REQ-SYNC-006): a headless member of one org that holds
//! all data, stays connected (reconnecting with backoff), announces itself as
//! always-on so the relay prefers it as catch-up partner, catches up periodically
//! and rotates its group key (REQ-ENC-003).
//!
//! Everything lives in one data directory:
//! - `device.key`: the 32-byte device secret (created on first run, mode 0600),
//! - `kith.db`: the SQLite store (data, MLS state, membership),
//! - `org`, `relay`: what it joined (written by [`join`]),
//! - `rotated`: when it last rotated its key (milliseconds since the epoch).

use std::path::{Path, PathBuf};
use std::time::Duration;

use kith_client::{Client, DeviceKey, Event, Signer};
use kith_net::{LiveClient, NetError};
use kith_store::SqliteStore;

/// Errors of the always-on client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading or writing the data directory failed.
    #[error("data directory: {0}")]
    Io(#[from] std::io::Error),
    /// The data directory is incomplete or corrupt.
    #[error("{0}")]
    Config(String),
    /// Network or client failure.
    #[error(transparent)]
    Net(#[from] NetError),
    /// Client failure.
    #[error(transparent)]
    Client(#[from] kith_client::ClientError),
    /// Store failure.
    #[error(transparent)]
    Store(#[from] kith_client::StoreError),
}

/// How the client behaves while running.
#[derive(Clone, Debug)]
pub struct Options {
    /// Ask a peer for missed changes this often (and after every reconnect).
    pub catch_up_every: Duration,
    /// Rotate the group key when the last rotation is older than this.
    pub rotate_every: Duration,
    /// Longest wait between reconnect attempts.
    pub max_backoff: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            catch_up_every: Duration::from_secs(10 * 60),
            rotate_every: Duration::from_secs(7 * 24 * 3600),
            max_backoff: Duration::from_secs(60),
        }
    }
}

type Store = SqliteStore;

fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

/// The device key of `dir`, created on first use.
fn device_key(dir: &Path) -> Result<DeviceKey, Error> {
    let p = path(dir, "device.key");
    if let Ok(bytes) = std::fs::read(&p) {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Config(format!("{} must hold 32 bytes", p.display())))?;
        return Ok(DeviceKey::from_secret_bytes(&seed));
    }
    create_data_dir(dir)?;
    let key = DeviceKey::generate();
    // Created with mode 0600 from the start (no window in which others can read it);
    // `create_new` fails if another process wrote a key meanwhile: use that one.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(&p) {
        Ok(mut f) => {
            std::io::Write::write_all(&mut f, &key.secret_bytes())?;
            f.sync_all()?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => device_key(dir),
        Err(e) => Err(e.into()),
    }
}

/// Create the data directory, accessible by its owner only (mode 0700 on Unix).
fn create_data_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

fn open_client(dir: &Path) -> Result<Client<Store>, Error> {
    let key = device_key(dir)?;
    let store = SqliteStore::open(path(dir, "kith.db"))?;
    Ok(Client::new(key, store)?)
}

fn read(dir: &Path, name: &str) -> Result<String, Error> {
    std::fs::read_to_string(path(dir, name))
        .map(|s| s.trim().to_string())
        .map_err(|_| Error::Config(format!("{name} missing in {}: join first", dir.display())))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Join an org with an invite link: connect to its relay, claim, and wait until an
/// admin accepts (up to `wait`). `on_code` gets the short code to compare with the
/// admin's screen. Returns the org ID.
pub async fn join(
    dir: &Path,
    link: &str,
    wait: Duration,
    mut on_code: impl FnMut(&str),
) -> Result<String, Error> {
    let info =
        kith_client::Invite::parse(link).map_err(|e| Error::Config(format!("invite: {e}")))?;
    let (org, relay) = (info.org.to_hex(), info.relay.clone());
    let client = open_client(dir)?;
    let mut live = LiveClient::connect(&relay, &org, client).await?;
    live.claim(link).await?;
    let joined = tokio::time::timeout(wait, async {
        loop {
            match live.next_event().await? {
                Some(Event::ClaimCode { org: o, code, .. }) if o == org => on_code(&code),
                Some(Event::Joined { org: o }) if o == org => return Ok::<_, Error>(()),
                Some(_) => continue,
                None => return Err(Error::Config("relay closed the connection".into())),
            }
        }
    })
    .await
    .map_err(|_| Error::Config("not admitted in time".into()))?;
    joined?;
    std::fs::write(path(dir, "org"), &org)?;
    std::fs::write(path(dir, "relay"), &relay)?;
    let _ = live.into_client().await;
    Ok(org)
}

/// Run until `stop` resolves: stay connected to the org's relay, answer catch-up
/// requests, catch up periodically and rotate the group key when due.
pub async fn run(
    dir: &Path,
    options: Options,
    stop: impl std::future::Future<Output = ()>,
) -> Result<(), Error> {
    let org = read(dir, "org")?;
    let relay = read(dir, "relay")?;
    let mut client = open_client(dir)?;
    client.set_always_on(true);
    // It holds everything, files included, so others can always fetch from it.
    client.set_fetch_files(true);
    tracing::info!(device = %client.device_id(), %org, %relay, "always-on client starting");
    tokio::pin!(stop);
    let mut backoff = Duration::from_secs(1);
    loop {
        let live = tokio::select! {
            () = &mut stop => return Ok(()),
            r = LiveClient::connect(&relay, &org, client) => r,
        };
        let mut live = match live {
            Ok(l) => {
                backoff = Duration::from_secs(1);
                l
            }
            Err(e) => {
                tracing::warn!("connect failed: {e}; retrying in {backoff:?}");
                tokio::select! {
                    () = &mut stop => return Ok(()),
                    () = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(options.max_backoff);
                client = open_client(dir)?;
                client.set_always_on(true);
                client.set_fetch_files(true);
                continue;
            }
        };
        let reason = serve(dir, &mut live, &options, &mut stop).await;
        let stopping = matches!(reason, Ok(true));
        if let Err(e) = &reason {
            tracing::warn!("connection lost: {e}");
        }
        client = live.into_client().await;
        if stopping {
            return Ok(());
        }
        tokio::select! {
            () = &mut stop => return Ok(()),
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(options.max_backoff);
    }
}

/// One connection's lifetime. `Ok(true)`: stop requested; `Ok(false)`: the relay
/// closed the connection.
async fn serve(
    dir: &Path,
    live: &mut LiveClient<Store>,
    options: &Options,
    stop: &mut std::pin::Pin<&mut impl std::future::Future<Output = ()>>,
) -> Result<bool, Error> {
    live.catch_up().await?;
    let mut tick = tokio::time::interval(options.catch_up_every);
    tick.tick().await; // the first tick fires at once; we just caught up
    loop {
        rotate_if_due(dir, live, options).await?;
        tokio::select! {
            () = stop.as_mut() => return Ok(true),
            _ = tick.tick() => live.catch_up().await?,
            ev = live.next_event() => match ev? {
                None => return Ok(false),
                Some(ev) => log_event(&ev),
            },
        }
    }
}

/// Log an event without the data it carries: a received change is logged by ID,
/// never with its (decrypted) payload.
fn log_event(ev: &Event) {
    match ev {
        Event::Received {
            org,
            from,
            change,
            is_new,
        } => tracing::debug!(
            %org,
            %from,
            change = %change.change_id.to_hex(),
            object = %change.body.object_id.to_hex(),
            is_new,
            "received a change"
        ),
        ev => tracing::debug!(?ev, "event"),
    }
}

async fn rotate_if_due(
    dir: &Path,
    live: &mut LiveClient<Store>,
    options: &Options,
) -> Result<(), Error> {
    let last: u64 = read(dir, "rotated")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let now = now_ms();
    if now.saturating_sub(last) < options.rotate_every.as_millis() as u64 {
        return Ok(());
    }
    let org = live.org().to_string();
    let frame = live.client_mut().rotate_key(&org)?;
    live.send(&[frame]).await?;
    std::fs::write(path(dir, "rotated"), now.to_string())?;
    tracing::info!("rotated the group key");
    Ok(())
}

/// A passphrase-encrypted backup of the client in `dir` (ADR 0010). The always-on
/// client holds everything, so this is the org's best backup.
pub fn export_backup(dir: &Path, passphrase: &str) -> Result<Vec<u8>, Error> {
    Ok(open_client(dir)?.export_backup(passphrase)?)
}

/// Set up `dir` (which must not hold a device yet) from a backup, to run against
/// `relay`. Returns the org. The client rejoins its group once a member is online.
pub fn restore_backup(
    dir: &Path,
    backup: &[u8],
    passphrase: &str,
    relay: &str,
) -> Result<String, Error> {
    if path(dir, "device.key").exists() {
        return Err(Error::Config(format!(
            "{} already holds a device",
            dir.display()
        )));
    }
    create_data_dir(dir)?;
    let store = SqliteStore::open(path(dir, "kith.db"))?;
    let client = Client::import_backup(backup, passphrase, store)?;
    let org = client
        .default_scope()?
        .org_id()
        .map(|o| o.to_hex())
        .ok_or_else(|| Error::Config("the backup is not of an org member".into()))?;
    std::fs::write(path(dir, "device.key"), client.signer().secret_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path(dir, "device.key"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
    std::fs::write(path(dir, "org"), &org)?;
    std::fs::write(path(dir, "relay"), relay)?;
    Ok(org)
}

/// The device ID of the always-on client in `dir` (creating its key if needed).
pub fn device_id(dir: &Path) -> Result<String, Error> {
    Ok(device_key(dir)?.device_id().to_hex())
}

#[cfg(test)]
mod tests;
