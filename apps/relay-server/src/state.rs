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

    /// Whether this store can keep revocation notices (optional, ADR 0014).
    fn keeps_revocations(&self) -> bool {
        false
    }

    /// All stored revocation notices.
    fn revocations(&self) -> BoxFuture<'_, Result<Vec<RevocationRecord>, String>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Store one notice (idempotent).
    fn save_revocation<'a>(
        &'a self,
        _rec: &'a RevocationRecord,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async { Err("this store cannot keep revocations".to_string()) })
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

/// A verified revocation notice as stored (ADR 0014).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    /// Org ID.
    pub org: String,
    /// The revoked device.
    pub device: String,
    /// The signed notice, hex (`Revocation::to_hex`), verified again when loaded.
    pub notice: String,
}

/// Load the stored notices into the relay. Each is verified against its org ID again;
/// bad ones are skipped. Returns how many revoked devices the relay now knows.
pub fn load_revocations(state: &Shared, records: &[RevocationRecord]) -> usize {
    let mut r = state.lock().unwrap();
    let mut n = 0;
    for rec in records {
        let Ok(org_key) = kith_core::DeviceId::from_hex(&rec.org) else {
            continue;
        };
        // `persist` is off while loading, so nothing is written back.
        match crate::remember_revocation(&mut r, &rec.org, &org_key, &rec.notice) {
            Ok(true) => n += 1,
            Ok(false) => {}
            Err(e) => tracing::warn!(org = %rec.org, error = %e, "skipping a stored revocation"),
        }
    }
    n
}

/// Start writing newly accepted notices to `store`. Call after [`load_revocations`].
/// A failed write is retried a few times, then logged: the notice stays in RAM and the
/// issuing admin repeats it on its next announce anyway (ADR 0013).
pub fn spawn_revocation_writer(
    state: &Shared,
    store: Arc<dyn StateStore>,
) -> tokio::task::JoinHandle<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<RevocationRecord>();
    state.lock().unwrap().persist = Some(tx);
    tokio::spawn(async move {
        while let Some(rec) = rx.recv().await {
            let mut delay = Duration::from_millis(500);
            for attempt in 1..=5 {
                match store.save_revocation(&rec).await {
                    Ok(()) => break,
                    Err(e) if attempt == 5 => {
                        tracing::error!(org = %rec.org, device = %rec.device, error = %e, "could not store a revocation");
                    }
                    Err(_) => {
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                }
            }
        }
    })
}
