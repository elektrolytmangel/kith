//! The WebSocket front end: upgrade, per-connection loop, writes.

use super::*;

/// The relay's HTTP/WebSocket routes (`/healthz`, `/v1/ws`).
pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
}

pub(crate) async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Shared>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
) -> Response {
    let (open, limits, per_ip) = {
        let r = state.lock().unwrap_or_else(PoisonError::into_inner);
        (r.open.clone(), r.limits.clone(), r.per_ip.clone())
    };
    let ip = peer.and_then(|Extension(ConnectInfo(addr))| {
        client_ip(addr.ip(), &headers, limits.client_ip_header.as_deref())
    });
    let ip_guard = match ip {
        Some(ip) if limits.max_connections_per_ip > 0 => {
            let mut m = per_ip.lock().unwrap_or_else(PoisonError::into_inner);
            let n = m.entry(ip).or_default();
            if *n >= limits.max_connections_per_ip {
                return (StatusCode::TOO_MANY_REQUESTS, "too many connections").into_response();
            }
            *n += 1;
            Some(IpGuard(per_ip.clone(), ip))
        }
        _ => None,
    };
    if open.fetch_add(1, Ordering::Relaxed) >= limits.max_connections {
        open.fetch_sub(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
    }
    let guard = OpenGuard(open);
    ws.max_message_size(limits.max_message_bytes)
        .max_frame_size(limits.max_message_bytes)
        .on_upgrade(move |socket| async move {
            let _guards = (guard, ip_guard);
            connection(socket, state, limits).await
        })
}

/// The address a connection is counted under: the TCP peer, or the last entry of
/// `header` (set by a trusted proxy) when configured. IPv6 addresses count per /64.
pub(crate) fn client_ip(peer: IpAddr, headers: &HeaderMap, header: Option<&str>) -> Option<IpAddr> {
    let ip = match header {
        Some(h) => headers
            .get_all(h)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .next_back()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(peer),
        None => peer,
    };
    Some(match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    })
}

/// Counts a connection for its client address for as long as it lives.
pub(crate) struct IpGuard(
    pub(crate) Arc<Mutex<HashMap<IpAddr, usize>>>,
    pub(crate) IpAddr,
);

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

pub(crate) async fn connection(mut socket: WebSocket, state: Shared, limits: Limits) {
    let mut frames = Bucket::new(limits.device_frames_per_sec, limits.device_burst);
    let mut bytes = Bucket::new(
        limits.device_bytes_per_sec,
        limits.device_bytes_per_sec * 4.0,
    );
    let mut refused = 0u32;
    let (tx, mut rx) = Tx::new(limits.max_queued_bytes);
    let (conn_id, auth_timeout) = {
        let r = state.lock().unwrap_or_else(PoisonError::into_inner);
        (r.next_conn.fetch_add(1, Ordering::Relaxed), r.auth_timeout)
    };
    let mut session = Session::New;
    let deadline = tokio::time::sleep(auth_timeout);
    tokio::pin!(deadline);
    let idle = limits.idle_timeout;
    let mut ping = tokio::time::interval(if idle.is_zero() {
        Duration::from_secs(3600)
    } else {
        idle / 3
    });
    ping.tick().await; // the first tick is immediate
    let mut last_heard = Instant::now();
    let write = limits.write_timeout;
    let close = tx.close.clone();

    loop {
        let authed = matches!(session, Session::Authed(_));
        tokio::select! {
            out = rx.recv() => match out {
                Some((f, n)) => {
                    tx.queued.fetch_sub(n, Ordering::Relaxed);
                    let Ok(bytes) = encode(&f) else { continue };
                    // A device that does not read is closed, not buffered for.
                    if !matches!(
                        tokio::time::timeout(write, socket.send(Message::Binary(bytes.into()))).await,
                        Ok(Ok(()))
                    ) {
                        tracing::debug!("write failed or timed out; closing");
                        break;
                    }
                }
                None => break,
            },
            () = close.notified() => break,
            () = &mut deadline, if !authed => {
                tracing::debug!("authentication timed out");
                send_now(&mut socket, error("auth-timeout", "authenticate within the time limit".into()), write).await;
                break;
            }
            _ = ping.tick(), if !idle.is_zero() => {
                if last_heard.elapsed() >= idle {
                    tracing::debug!("idle timeout");
                    send_now(&mut socket, error("idle-timeout", "nothing received; closing".into()), write).await;
                    break;
                }
                if !matches!(
                    tokio::time::timeout(write, socket.send(Message::Ping(Vec::new().into()))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            msg = socket.recv() => {
                let Some(Ok(msg)) = msg else { break };
                last_heard = Instant::now();
                let raw = match msg {
                    Message::Binary(b) => b.to_vec(),
                    Message::Text(t) => t.as_bytes().to_vec(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                // Abuse limits (REQ-RELAY-006): drop excess frames, close persistent abusers.
                if !(frames.take(1.0) && bytes.take(raw.len() as f64)) {
                    refused += 1;
                    if refused >= limits.max_refused {
                        send_now(&mut socket, error("rate-limited", "too many frames; closing".into()), write).await;
                        break;
                    }
                    if refused.is_power_of_two() {
                        send(&tx, error("rate-limited", "slow down: frame dropped".into()));
                    }
                    continue;
                }
                refused = 0;
                match decode(&raw) {
                    Ok(frame) => {
                        // Signatures are checked here, without the relay lock; an
                        // announce (many signatures) on the blocking pool.
                        let checked = if matches!(frame, Frame::Announce { .. }) {
                            let device = match &session {
                                Session::Authed(d) => Some(d.clone()),
                                _ => None,
                            };
                            match tokio::task::spawn_blocking(move || check_frame(frame, None, device.as_deref())).await {
                                Ok(c) => c,
                                Err(_) => break,
                            }
                        } else {
                            check_frame(frame, Some(&session), None)
                        };
                        if handle(checked, &mut session, conn_id, &tx, &state) == Flow::Close {
                            // Flush the queued error frame, then hang up.
                            while let Ok((f, _)) = rx.try_recv() {
                                send_now(&mut socket, f, write).await;
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        send(&tx, error("bad-frame", e.to_string()));
                    }
                }
            }
        }
    }

    // Say goodbye properly so clients see a clean close, not a reset.
    let _ = tokio::time::timeout(write, socket.send(Message::Close(None))).await;

    if let Session::Authed(d) = session {
        let mut r = state.lock().unwrap_or_else(PoisonError::into_inner);
        // A newer connection of the same device may have replaced this one; only
        // clean up if this connection still owns the device's slot.
        if r.conns.get(&d).is_some_and(|c| c.id == conn_id) {
            let orgs = r.table.orgs_of(&d);
            r.table.disconnect(&d);
            for org in orgs {
                forget_if_empty(&mut r, &org);
            }
            r.proofs.remove(&d);
            r.conns.remove(&d);
            tracing::debug!(device = %d, "disconnected");
        }
    }
}

pub(crate) async fn send_now(socket: &mut WebSocket, frame: Frame, write: Duration) {
    if let Ok(bytes) = encode(&frame) {
        let _ = tokio::time::timeout(write, socket.send(Message::Binary(bytes.into()))).await;
    }
}
