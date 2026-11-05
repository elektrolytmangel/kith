//! Azure Table state against Azurite. Skipped unless `KITH_AZURITE_CONNECTION_STRING` is set
//! (CI starts the emulator; locally: `docker run -p 10002:10002 mcr.microsoft.com/azure-storage/azurite
//! azurite-table --tableHost 0.0.0.0 --skipApiVersionCheck`).
#![cfg(feature = "azure-state")]

use std::collections::HashSet;

use kith_relay_server::state::{RevocationRecord, StateStore, azure::AzureTables};

/// req: REQ-RELAY-008
#[tokio::test]
async fn the_allowlist_lives_in_a_table() {
    let Ok(cs) = std::env::var("KITH_AZURITE_CONNECTION_STRING") else {
        eprintln!("KITH_AZURITE_CONNECTION_STRING is not set; skipping");
        return;
    };
    let table = format!("t{}", std::process::id());
    let t = AzureTables::from_connection_string(&cs, &table).unwrap();
    // Missing table: an error, not "serve everyone".
    assert!(t.allowed_orgs().await.is_err());
    t.ensure_table().await.unwrap();
    t.ensure_table().await.unwrap();
    // Empty table: nobody is approved.
    assert_eq!(t.allowed_orgs().await.unwrap(), Some(HashSet::new()));

    t.allow("AB12").await.unwrap();
    t.allow("ab12").await.unwrap();
    for i in 0..1200 {
        // Enough rows for the service to page the result (1000 per page).
        t.allow(&format!("{i:04x}")).await.unwrap();
    }
    let all = t.allowed_orgs().await.unwrap().unwrap();
    assert_eq!(all.len(), 1201);
    assert!(all.contains("ab12"));

    t.disallow("ab12").await.unwrap();
    t.disallow("ab12").await.unwrap();
    assert!(!t.list().await.unwrap().contains("ab12"));

    // Revocation notices (ADR 0014): stored per device, replaced on a repeat, paged.
    assert!(t.revocations().await.unwrap().is_empty());
    let rec = |i: usize, notice: &str| RevocationRecord {
        org: "aabb".into(),
        device: format!("{i:04x}"),
        notice: notice.into(),
    };
    for i in 0..1100 {
        t.save_revocation(&rec(i, "n1")).await.unwrap();
    }
    t.save_revocation(&rec(0, "n2")).await.unwrap();
    let all = t.revocations().await.unwrap();
    assert_eq!(all.len(), 1100);
    assert!(all.contains(&rec(0, "n2")));
}
