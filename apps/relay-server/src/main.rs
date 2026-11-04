//! Standalone kith relay binary. See the library docs for the protocol and configuration.

use std::time::Duration;

use kith_relay_server::{Limits, app, new_state_with};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr = std::env::var("KITH_RELAY_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let auth_timeout = std::env::var("KITH_RELAY_AUTH_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_secs(10), Duration::from_secs);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!(%addr, version = kith_protocol::PROTOCOL_VERSION, "kith relay listening");
    axum::serve(
        listener,
        app(new_state_with(auth_timeout, Limits::from_env())),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .expect("server");
}
