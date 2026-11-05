//! Standalone kith relay binary. See the library docs for the protocol and configuration.

use std::time::Duration;

use std::sync::Arc;

use kith_relay_server::{
    Limits, app, new_state_with, parse_allowed_orgs,
    state::{StateStore, StaticState, refresh_allowlist, spawn_allowlist_refresh},
};

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
    let state = new_state_with(auth_timeout, Limits::from_env());
    let store = state_store();
    if let Err(e) = refresh_allowlist(&state, store.as_ref()).await {
        tracing::error!(error = %e, "cannot read the allowed organizations");
        std::process::exit(1);
    }
    let refresh = std::env::var("KITH_RELAY_ALLOWLIST_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    if store.refreshes() {
        spawn_allowlist_refresh(state.clone(), store, Duration::from_secs(refresh.max(1)));
    }
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!(%addr, version = kith_protocol::PROTOCOL_VERSION, "kith relay listening");
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}

/// Azure Table Storage if configured, else the fixed list from `KITH_RELAY_ALLOWED_ORGS`.
fn state_store() -> Arc<dyn StateStore> {
    let azure_set = std::env::var_os("KITH_RELAY_AZURE_STORAGE_ACCOUNT").is_some()
        || std::env::var_os("KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING").is_some();
    if azure_set {
        #[cfg(feature = "azure-state")]
        match kith_relay_server::state::azure::AzureTables::from_env() {
            Ok(Some(t)) => {
                tracing::info!("approved organizations come from Azure Table Storage");
                return Arc::new(t);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "invalid Azure storage configuration");
                std::process::exit(1);
            }
        }
        #[cfg(not(feature = "azure-state"))]
        {
            tracing::error!(
                "Azure storage is configured but this build lacks the `azure-state` feature"
            );
            std::process::exit(1);
        }
    }
    let allowed = std::env::var("KITH_RELAY_ALLOWED_ORGS")
        .ok()
        .and_then(|list| parse_allowed_orgs(&list));
    match &allowed {
        Some(orgs) => tracing::info!(orgs = orgs.len(), "serving only the allowed organizations"),
        None => tracing::warn!("KITH_RELAY_ALLOWED_ORGS is not set: serving every organization"),
    }
    Arc::new(StaticState(allowed))
}
