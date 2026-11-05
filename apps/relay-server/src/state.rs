//! Durable relay state behind a trait (Azure plan step 2).
//!
//! The relay keeps connections, challenges and rate buckets in RAM; none of that can move to
//! storage. What *can* be durable is configuration the operator manages: today the list of
//! approved organizations (REQ-RELAY-008). [`StateStore`] is where that list comes from;
//! [`spawn_allowlist_refresh`] re-reads it so approving an org needs no restart.

use std::{collections::HashSet, future::Future, pin::Pin, sync::Arc, time::Duration};

use crate::{Shared, set_allowed_orgs};

#[cfg(feature = "azure-state")]
pub mod azure;

/// A boxed future, so [`StateStore`] can be used as a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Where the relay reads operator-managed state from.
pub trait StateStore: Send + Sync {
    /// The approved org IDs (lower case). `None` serves every org; `Some(empty)` serves none,
    /// so a store that is configured but empty fails closed.
    fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>>;

    /// Whether the list can change while the relay runs (so it is worth re-reading).
    fn refreshes(&self) -> bool {
        true
    }
}

/// A fixed list, for example from `KITH_RELAY_ALLOWED_ORGS`. The default store.
pub struct StaticState(pub Option<HashSet<String>>);

impl StateStore for StaticState {
    fn refreshes(&self) -> bool {
        false
    }

    fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

/// Read the allowlist once and apply it. On error the previous list stays in force.
pub async fn refresh_allowlist(state: &Shared, store: &dyn StateStore) -> Result<(), String> {
    let orgs = store.allowed_orgs().await?;
    set_allowed_orgs(state, orgs);
    Ok(())
}

/// Re-read the allowlist every `every`. Orgs removed from it lose their online devices.
/// A failed read is logged and the last good list stays.
pub fn spawn_allowlist_refresh(
    state: Shared,
    store: Arc<dyn StateStore>,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick is immediate; main loaded the list at start
        loop {
            tick.tick().await;
            if let Err(e) = refresh_allowlist(&state, store.as_ref()).await {
                tracing::warn!(error = %e, "could not refresh the allowed organizations; keeping the last list");
            }
        }
    })
}
