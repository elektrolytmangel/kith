//! Frame checks before routing, and the per-connection session state machine.

use super::*;

#[derive(PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Close,
}

/// A frame with its signatures checked. Checking needs no shared state, so it
/// happens before the relay lock is taken.
pub(crate) enum Checked {
    /// `auth`, with whether its signature matches the challenged key.
    Auth(bool),
    /// `announce`, each org's proof and notices checked.
    Announce(Vec<CheckedOrg>),
    /// Refused as a whole with this error.
    Refuse(Frame),
    /// Any other frame, unchanged.
    Frame(Frame),
}

/// One org of an announce, its signatures checked.
pub(crate) struct CheckedOrg {
    /// Canonical org ID.
    pub(crate) org: String,
    pub(crate) always_on: bool,
    /// The role the proof gives (signatures only; revocations are checked under the lock).
    pub(crate) proof: Result<(Role, Option<CertChain>), &'static str>,
    /// Whether the announce carried revocation notices for this org.
    pub(crate) sent_notices: bool,
    /// The notices, verified, with their hex form (only for an admin's proof).
    pub(crate) notices: Vec<Result<(Revocation, String), String>>,
}

/// Check the signatures in `frame`: an `auth` against the challenge in `session`,
/// an `announce` by the authenticated `device`.
pub(crate) fn check_frame(
    frame: Frame,
    session: Option<&Session>,
    device: Option<&str>,
) -> Checked {
    match (frame, session, device) {
        (Frame::Auth { signature }, Some(Session::Challenged { device, nonce }), _) => {
            let sig = hex::decode(&signature)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok());
            Checked::Auth(sig.is_some_and(|s| {
                verify_signature(device, &auth_message(&device.to_hex(), nonce), &s).is_ok()
            }))
        }
        (frame @ Frame::Announce { .. }, _, Some(d)) => {
            let orgs = match canonical_frame(frame) {
                Ok(Frame::Announce { orgs }) => orgs,
                Ok(other) => return Checked::Frame(other),
                Err(org) => return Checked::Refuse(bad_org(&org)),
            };
            if orgs.len() > MAX_ORGS_PER_ANNOUNCE {
                return Checked::Refuse(error(
                    "too-many-orgs",
                    format!("announce at most {MAX_ORGS_PER_ANNOUNCE} orgs at a time"),
                ));
            }
            let mut budget = MAX_NOTICES_PER_ANNOUNCE;
            let checked = orgs
                .into_iter()
                .map(|m| {
                    let proof = verify_proof(&m.org, d, &m.proof);
                    let mut notices = vec![];
                    if matches!(proof, Ok((Role::Admin, _))) {
                        let org_key = DeviceId::from_hex(&m.org).expect("canonical");
                        let take = m.revoked.len().min(budget);
                        budget -= take;
                        notices = m
                            .revoked
                            .iter()
                            .take(take)
                            .map(|n| verify_notice(&org_key, n).map(|rev| (rev, n.clone())))
                            .collect();
                    }
                    CheckedOrg {
                        sent_notices: !m.revoked.is_empty(),
                        org: m.org,
                        always_on: m.always_on,
                        proof,
                        notices,
                    }
                })
                .collect();
            Checked::Announce(checked)
        }
        (frame, _, _) => Checked::Frame(frame),
    }
}

pub(crate) fn handle(
    checked: Checked,
    session: &mut Session,
    conn_id: u64,
    tx: &Tx,
    state: &Shared,
) -> Flow {
    let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
    // Handshake first: nothing else is accepted before the device is authenticated.
    match (&*session, checked) {
        (Session::New, Checked::Frame(Frame::Hello { version, device })) => {
            if !supports_version(version) {
                send(
                    tx,
                    error(
                        "version",
                        format!("relay speaks v{MIN_PROTOCOL_VERSION} to v{PROTOCOL_VERSION}"),
                    ),
                );
                return Flow::Close;
            }
            let Ok(id) = DeviceId::from_hex(&device) else {
                send(
                    tx,
                    error(
                        "bad-device",
                        "device must be a hex Ed25519 public key".into(),
                    ),
                );
                return Flow::Close;
            };
            let nonce = hex::encode(kith_core::random_bytes::<32>());
            send(
                tx,
                Frame::Challenge {
                    nonce: nonce.clone(),
                },
            );
            *session = Session::Challenged { device: id, nonce };
            Flow::Continue
        }
        (Session::Challenged { device, .. }, Checked::Auth(ok)) => {
            if !ok {
                send(
                    tx,
                    error(
                        "auth-failed",
                        "signature does not match the device key".into(),
                    ),
                );
                return Flow::Close;
            }
            let device_hex = device.to_hex();
            // A reconnecting device replaces its old connection, which is closed.
            if let Some(old) = r.conns.insert(
                device_hex.clone(),
                Conn {
                    id: conn_id,
                    tx: tx.clone(),
                },
            ) {
                old.tx.close();
            }
            tracing::debug!(device = %device_hex, "authenticated");
            *session = Session::Authed(device_hex);
            Flow::Continue
        }
        (Session::Authed(_), Checked::Frame(Frame::Hello { .. } | Frame::Auth { .. })) => {
            send(tx, error("unsupported", "already authenticated".into()));
            Flow::Continue
        }
        (Session::Authed(d), Checked::Announce(orgs)) => {
            let d = d.clone();
            announce(orgs, &d, tx, &mut r);
            Flow::Continue
        }
        (Session::Authed(_), Checked::Refuse(f)) => {
            send(tx, f);
            Flow::Continue
        }
        (Session::Authed(d), Checked::Frame(frame)) => {
            let d = d.clone();
            route(frame, &d, tx, &mut r);
            Flow::Continue
        }
        (Session::New, _) => {
            send(tx, error("unauthenticated", "send hello first".into()));
            Flow::Continue
        }
        (Session::Challenged { .. } | Session::Authed(_), _) => {
            send(
                tx,
                error(
                    "unauthenticated",
                    "answer the challenge with auth first".into(),
                ),
            );
            Flow::Continue
        }
    }
}

/// The role a membership proof gives `device` in `org` (REQ-RELAY-004), from its
/// signatures alone. An empty proof means "joining": pending.
pub(crate) fn verify_proof(
    org: &str,
    device: &str,
    proof: &str,
) -> Result<(Role, Option<CertChain>), &'static str> {
    let org_key = DeviceId::from_hex(org).map_err(|_| "org ID must be the hex org root key")?;
    if proof.is_empty() {
        return Ok((Role::Pending, None));
    }
    let device = DeviceId::from_hex(device).map_err(|_| "bad device")?;
    let chain = CertChain::from_hex(proof).map_err(|_| "malformed membership proof")?;
    let proven = chain
        .verify(&org_key, &device)
        .map_err(|_| "membership proof does not verify")?;
    let role = if proven.admin {
        Role::Admin
    } else {
        Role::Member
    };
    Ok((role, Some(chain)))
}
