//! `kith-always-on --data DIR [--join LINK]`: run a headless always-on member.
//!
//! First run: `--join` with an invite link from an admin; the client prints the
//! short code to compare, waits until it is admitted, then keeps running. Later
//! runs need only `--data`.
//!
//! Backups (passphrase in `KITH_BACKUP_PASSPHRASE`): `--export-backup FILE` writes
//! one and exits; `--restore-backup FILE --relay URL` sets up an empty data
//! directory from one, then runs.

use std::path::PathBuf;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: kith-always-on --data DIR [--join INVITE_LINK | --restore-backup FILE --relay URL | --export-backup FILE] [--catch-up-secs N] [--rotate-days N]"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let (mut data, mut link) = (None, None);
    let (mut export, mut restore, mut relay) = (None, None, None);
    let mut options = kith_always_on::Options::default();
    while let Some(a) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--data" => data = Some(PathBuf::from(value())),
            "--join" => link = Some(value()),
            "--export-backup" => export = Some(PathBuf::from(value())),
            "--restore-backup" => restore = Some(PathBuf::from(value())),
            "--relay" => relay = Some(value()),
            "--catch-up-secs" => {
                options.catch_up_every =
                    Duration::from_secs(value().parse().unwrap_or_else(|_| usage()))
            }
            "--rotate-days" => {
                let days: u64 = value().parse().unwrap_or_else(|_| usage());
                options.rotate_every = Duration::from_secs(days * 24 * 3600)
            }
            _ => usage(),
        }
    }
    let Some(dir) = data else { usage() };
    let passphrase = || {
        std::env::var("KITH_BACKUP_PASSPHRASE").unwrap_or_else(|_| {
            eprintln!("set KITH_BACKUP_PASSPHRASE");
            std::process::exit(2)
        })
    };
    if let Some(file) = export {
        match kith_always_on::export_backup(&dir, &passphrase()).map(|b| std::fs::write(&file, b)) {
            Ok(Ok(())) => {
                println!("backup written to {}", file.display());
                return;
            }
            Ok(Err(e)) => eprintln!("writing the backup: {e}"),
            Err(e) => eprintln!("backup failed: {e}"),
        }
        std::process::exit(1)
    }
    if let Some(file) = restore {
        let Some(relay) = relay.as_deref() else {
            usage()
        };
        let restored = std::fs::read(&file)
            .map_err(kith_always_on::Error::from)
            .and_then(|b| kith_always_on::restore_backup(&dir, &b, &passphrase(), relay));
        match restored {
            Ok(org) => println!("restored a member of {org}; it rejoins once a member is online"),
            Err(e) => {
                eprintln!("restore failed: {e}");
                std::process::exit(1)
            }
        }
    }
    if let Some(link) = link {
        match kith_always_on::join(&dir, &link, Duration::from_secs(15 * 60), |code| {
            println!("short code: {code} (compare it with the admin's screen)");
        })
        .await
        {
            Ok(org) => println!("joined {org}"),
            Err(e) => {
                eprintln!("join failed: {e}");
                std::process::exit(1)
            }
        }
    }
    let stop = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    if let Err(e) = kith_always_on::run(&dir, options, stop).await {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
