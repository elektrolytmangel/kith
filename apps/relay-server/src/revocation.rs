//! Signed revocation notices (REQ-INV-004, ADR 0013/0018).

use super::*;

/// Refuse a device a revocation reaches: through its chain, or, pending (no
/// chain), by name. A revoked device does not come back as a newcomer.
pub(crate) fn not_revoked(
    device: &str,
    chain: Option<&CertChain>,
    revoked: Option<&HashMap<String, Revoked>>,
) -> Result<(), &'static str> {
    let hit = revoked.is_some_and(|set| match chain {
        Some(c) => chain_revoked(c, set),
        None => set.contains_key(device),
    });
    if hit {
        Err("device was revoked")
    } else {
        Ok(())
    }
}

/// Parse and verify one revocation notice against the org key.
pub(crate) fn verify_notice(org_key: &DeviceId, notice: &str) -> Result<Revocation, String> {
    Revocation::from_hex(notice)
        .and_then(|rev| rev.verify(org_key).map(|_| rev))
        .map_err(|e| e.to_string())
}

/// Remember a verified notice's device as revoked; `Ok(true)` if it changed
/// anything. A notice by an admin the root revoked does not count (when `loading`
/// stored notices: unless it is older than that revocation). New notices are
/// handed to the persistence writer when it is on.
pub(crate) fn remember_verified(
    r: &mut Relay,
    org: &str,
    rev: &Revocation,
    notice: &str,
    loading: bool,
) -> Result<bool, String> {
    let device = rev.device.to_hex();
    let set = r.revoked.get(org);
    if !rev.by_root()
        && let Some(e) = set
            .and_then(|s| s.get(&rev.issuer.to_hex()))
            .filter(|e| e.by_root)
        && !(loading && rev.issued_ms < e.issued_ms)
    {
        return Err("the issuer was revoked".into());
    }
    let entry = Revoked {
        by_root: rev.by_root(),
        issued_ms: rev.issued_ms,
    };
    let new = match set.and_then(|s| s.get(&device)) {
        Some(e) if e.by_root || !entry.by_root => false,
        // A root notice for a device only an admin had revoked.
        Some(_) => true,
        None if set.map_or(0, HashMap::len) >= MAX_REVOKED_PER_ORG => false,
        None if r.revoked_total >= MAX_REVOKED_TOTAL => {
            tracing::warn!(%org, "the relay's revocation list is full; a notice was not kept");
            return Err("the relay's revocation list is full".into());
        }
        None => {
            r.revoked_total += 1;
            true
        }
    };
    if !new {
        return Ok(false);
    }
    r.revoked
        .entry(org.to_string())
        .or_default()
        .insert(device.clone(), entry);
    if let Some(tx) = &r.persist {
        let _ = tx.send(state::RevocationRecord {
            org: org.to_string(),
            device,
            notice: notice.to_string(),
        });
    }
    Ok(true)
}

/// Verify and remember the revocation notices of an announce, then remove every
/// online device of `org` they affect (the revoked ones and devices certified
/// through them). Bad notices are ignored with an error to `tx`.
pub(crate) fn apply_revocations(
    r: &mut Relay,
    org: &str,
    notices: Vec<Result<(Revocation, String), String>>,
    tx: &Tx,
) {
    let mut added = false;
    for n in notices {
        match n.and_then(|(rev, hex)| remember_verified(r, org, &rev, &hex, false)) {
            Ok(new) => added |= new,
            Err(e) => {
                send(tx, error("bad-revocation", format!("{org}: {e}")));
            }
        }
    }
    if !added {
        return;
    }
    let set = r.revoked.get(org).cloned().unwrap_or_default();
    let affected: Vec<String> = r
        .table
        .devices_in(org)
        .into_iter()
        .filter(|dev| {
            match r.proofs.get(dev).and_then(|m| m.get(org)) {
                Some(c) => chain_revoked(c, &set),
                // Pending devices have no chain.
                None => set.contains_key(dev),
            }
        })
        .collect();
    for dev in &affected {
        r.table.kick(dev, org);
        if let Some(m) = r.proofs.get_mut(dev) {
            m.remove(org);
        }
        if let Some(conn) = r.conns.get(dev) {
            send(
                &conn.tx,
                error("revoked", format!("{org}: device was removed")),
            );
        }
    }
    forget_if_empty(r, org);
    let online = r.table.online(org);
    fan_out(r, &online, || Frame::Presence {
        org: org.to_string(),
        online: online.clone(),
    });
}
