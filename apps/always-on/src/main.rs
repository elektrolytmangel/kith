//! `kith-always-on --data DIR [--join LINK]`: run a headless always-on member.
//!
//! First run: `--join -` reads an invite link from an admin on stdin (a link
//! given as the argument works too, but is visible in the process list and the
//! shell history); the client prints the short code to compare, waits until it is
//! admitted, then keeps running. Later runs need only `--data`.
//!
//! Backups: `--export-backup FILE` writes one and exits; `--restore-backup FILE
//! --relay URL` sets up an empty data directory from one, then runs. The
//! passphrase comes from the file named in `KITH_BACKUP_PASSPHRASE_FILE` (e.g. a
//! Docker secret), or from `KITH_BACKUP_PASSPHRASE` (visible to whoever can
//! inspect the process or container).

use std::path::PathBuf;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: kith-always-on --data DIR [--join - | --restore-backup FILE --relay URL | --export-backup FILE] [--catch-up-secs N] [--rotate-days N]\n  --join - reads the invite link from stdin"
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
    let passphrase = || match backup_passphrase() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
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
        let link = if link == "-" {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                eprint!("invite link: ");
            }
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() || line.trim().is_empty() {
                eprintln!("--join -: no invite link on stdin");
                std::process::exit(2)
            }
            line.trim().to_string()
        } else {
            tracing::warn!(
                "the invite link in the arguments is visible in the process list and shell history; prefer `--join -` and stdin"
            );
            link
        };
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

/// The backup passphrase: the contents of `KITH_BACKUP_PASSPHRASE_FILE` (one
/// trailing newline removed), else `KITH_BACKUP_PASSPHRASE`.
fn backup_passphrase() -> Result<String, String> {
    if let Some(file) = std::env::var_os("KITH_BACKUP_PASSPHRASE_FILE") {
        let text = std::fs::read_to_string(&file)
            .map_err(|e| format!("KITH_BACKUP_PASSPHRASE_FILE: {e}"))?;
        let p = text
            .strip_suffix('\n')
            .map(|p| p.strip_suffix('\r').unwrap_or(p))
            .unwrap_or(&text);
        if p.is_empty() {
            return Err("KITH_BACKUP_PASSPHRASE_FILE is empty".into());
        }
        return Ok(p.to_string());
    }
    match std::env::var("KITH_BACKUP_PASSPHRASE") {
        Ok(p) if !p.is_empty() => {
            tracing::warn!(
                "KITH_BACKUP_PASSPHRASE is visible to whoever can inspect the process or container; prefer KITH_BACKUP_PASSPHRASE_FILE"
            );
            Ok(p)
        }
        _ => Err("set KITH_BACKUP_PASSPHRASE_FILE (or KITH_BACKUP_PASSPHRASE)".into()),
    }
}
