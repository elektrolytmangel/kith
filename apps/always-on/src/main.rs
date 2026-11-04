//! `kith-always-on --data DIR [--join LINK]`: run a headless always-on member.
//!
//! First run: `--join` with an invite link from an admin; the client prints the
//! short code to compare, waits until it is admitted, then keeps running. Later
//! runs need only `--data`.

use std::path::PathBuf;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: kith-always-on --data DIR [--join INVITE_LINK] [--catch-up-secs N] [--rotate-days N]"
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
    let mut options = kith_always_on::Options::default();
    while let Some(a) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--data" => data = Some(PathBuf::from(value())),
            "--join" => link = Some(value()),
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
