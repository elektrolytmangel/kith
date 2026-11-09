//! Announce, route and deliver frames between devices.

use super::*;

/// Take one routed frame from `org`'s bucket, or its pending devices' bucket.
pub(crate) fn org_allows(r: &mut Relay, org: &str, pending: bool) -> bool {
    let (map, rate) = if pending {
        (&mut r.pending_buckets, r.limits.pending_frames_per_sec)
    } else {
        (&mut r.org_buckets, r.limits.org_frames_per_sec)
    };
    map.entry(org.to_string())
        .or_insert_with(|| Bucket::new(rate, rate * 2.0))
        .take(1.0)
}

/// Drop an org's rate buckets once none of its devices is online. Buckets exist only
/// for orgs with devices online, so their number stays bounded.
pub(crate) fn forget_if_empty(r: &mut Relay, org: &str) {
    if r.table.devices_in(org).is_empty() {
        r.org_buckets.remove(org);
        r.pending_buckets.remove(org);
    }
}

pub(crate) fn bad_org(org: &str) -> Frame {
    error(
        "bad-org",
        format!("{org}: org ID must be the hex org root key"),
    )
}

/// Apply an announce whose signatures are checked: join each org with the role its
/// proof gives, unless a revocation reaches the device. Only an admin's announce
/// feeds revocation notices, and they may revoke the announcer itself.
pub(crate) fn announce(orgs: Vec<CheckedOrg>, d: &str, tx: &Tx, r: &mut Relay) {
    for m in orgs {
        if let Some(allowed) = &r.allowed_orgs
            && !allowed.contains(&m.org)
        {
            send(
                tx,
                error(
                    "org-not-allowed",
                    format!("{}: this relay does not serve this organization", m.org),
                ),
            );
            continue;
        }
        let refuse = |why: &str| {
            let code = if why == "device was revoked" {
                "revoked"
            } else {
                "bad-proof"
            };
            send(tx, error(code, format!("{}: {why}", m.org)));
        };
        if r.table.role(&m.org, d).is_none() && r.table.orgs_of(d).len() >= MAX_ORGS_PER_DEVICE {
            send(
                tx,
                error(
                    "too-many-orgs",
                    format!(
                        "{}: a device is in at most {MAX_ORGS_PER_DEVICE} orgs at a time",
                        m.org
                    ),
                ),
            );
            continue;
        }
        let (role, chain) = match m.proof {
            Ok(x) => x,
            Err(why) => {
                refuse(why);
                continue;
            }
        };
        if let Err(why) = not_revoked(d, chain.as_ref(), r.revoked.get(&m.org)) {
            refuse(why);
            continue;
        }
        if m.sent_notices {
            if role != Role::Admin {
                send(
                    tx,
                    error(
                        "bad-revocation",
                        format!("{}: only admins send revocation notices", m.org),
                    ),
                );
            } else {
                apply_revocations(r, &m.org, m.notices, tx);
                if let Err(why) = not_revoked(d, chain.as_ref(), r.revoked.get(&m.org)) {
                    refuse(why);
                    continue;
                }
            }
        }
        match chain {
            Some(c) => {
                r.proofs
                    .entry(d.to_string())
                    .or_default()
                    .insert(m.org.clone(), c);
            }
            None => {
                if let Some(p) = r.proofs.get_mut(d) {
                    p.remove(&m.org);
                }
            }
        }
        r.table.join_as(d, &m.org, role);
        r.table
            .set_always_on(d, m.always_on && role != Role::Pending);
        if role != Role::Pending {
            let online = r.table.online(&m.org);
            fan_out(r, &online, || Frame::Presence {
                org: m.org.clone(),
                online: online.clone(),
            });
        }
    }
}

pub(crate) fn route(frame: Frame, d: &str, tx: &Tx, r: &mut Relay) {
    // One spelling per org, so revocations and routing see the same org.
    let frame = match canonical_frame(frame) {
        Ok(f) => f,
        Err(org) => {
            send(tx, bad_org(&org));
            return;
        }
    };
    let member =
        |r: &Relay, org: &str| matches!(r.table.role(org, d), Some(Role::Member | Role::Admin));
    let routed_org = match &frame {
        Frame::Broadcast { org, .. }
        | Frame::Direct { org, .. }
        | Frame::SyncRequest { org, .. }
        | Frame::InviteClaim { org, .. } => Some(org.clone()),
        _ => None,
    };
    if let Some(org) = routed_org
        && let Some(role) = r.table.role(&org, d)
        && !org_allows(r, &org, role == Role::Pending)
    {
        send(
            tx,
            error(
                "rate-limited",
                format!("org {org} is over its limit; frame dropped"),
            ),
        );
        return;
    }
    match frame {
        Frame::Broadcast { org, body } if member(r, &org) => {
            let route = r.table.broadcast(&org, d);
            deliver(r, route, tx, org, d, body);
        }
        Frame::Direct { org, to, body } if member(r, &org) => {
            let route = r.table.direct(&org, &to);
            deliver(r, route, tx, org, d, body);
        }
        Frame::SyncRequest { org, body } if member(r, &org) => {
            let route = r.table.sync_partner(&org, d);
            deliver(r, route, tx, org, d, body);
        }
        Frame::InviteClaim { org, body, to, .. } if r.table.role(&org, d).is_some() => {
            let route = match to {
                Some(to) => r.table.member(&org, &to),
                None => r.table.admins(&org),
            };
            // Its own frame type: the receiver takes nothing but a claim from it.
            let delivered = match route {
                Route::To(devs) => fan_out(r, &devs, || Frame::ClaimDeliver {
                    org: org.clone(),
                    from: d.into(),
                    body: body.clone(),
                }),
                Route::Dropped => vec![],
            };
            send(tx, Frame::Receipt { delivered });
        }
        Frame::Broadcast { org, .. }
        | Frame::Direct { org, .. }
        | Frame::SyncRequest { org, .. }
        | Frame::InviteClaim { org, .. } => send(
            tx,
            error(
                "not-a-member",
                format!("announce {org} with a valid proof first"),
            ),
        ),
        // Never echo the frame: it is the client's input, of any size.
        _ => send(
            tx,
            error("unsupported", "frame type not accepted from clients".into()),
        ),
    }
}

/// `frame` with its org IDs in canonical form; `Err(org)` for an invalid one.
pub(crate) fn canonical_frame(frame: Frame) -> Result<Frame, String> {
    let canon = |org: String| canonical_org(&org).ok_or(org);
    Ok(match frame {
        Frame::Announce { orgs } => Frame::Announce {
            orgs: orgs
                .into_iter()
                .map(|m| {
                    Ok(kith_protocol::Membership {
                        org: canon(m.org)?,
                        ..m
                    })
                })
                .collect::<Result<_, String>>()?,
        },
        Frame::Broadcast { org, body } => Frame::Broadcast {
            org: canon(org)?,
            body,
        },
        Frame::Direct { org, to, body } => Frame::Direct {
            org: canon(org)?,
            to,
            body,
        },
        Frame::SyncRequest { org, body } => Frame::SyncRequest {
            org: canon(org)?,
            body,
        },
        Frame::InviteClaim {
            org,
            token,
            body,
            to,
        } => Frame::InviteClaim {
            org: canon(org)?,
            token,
            body,
            to,
        },
        other => other,
    })
}

pub(crate) fn deliver(r: &Relay, route: Route, tx: &Tx, org: String, from: &str, body: Vec<u8>) {
    let delivered = match route {
        Route::To(devs) => fan_out(r, &devs, || Frame::Deliver {
            org: org.clone(),
            from: from.into(),
            body: body.clone(),
        }),
        Route::Dropped => vec![],
    };
    send(tx, Frame::Receipt { delivered });
}

/// Queue a frame for each of `to`; the devices it was queued for. A device whose
/// outbox is full misses it (it catches up by sync).
pub(crate) fn fan_out(r: &Relay, to: &[String], make: impl Fn() -> Frame) -> Vec<String> {
    to.iter()
        .filter(|d| r.conns.get(*d).is_some_and(|conn| queue(&conn.tx, make())))
        .cloned()
        .collect()
}

pub(crate) fn error(code: &str, message: String) -> Frame {
    Frame::Error {
        code: code.into(),
        message,
    }
}
