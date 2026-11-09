//! kith relay: WebSocket front end around `kith_relay::RoutingTable`.
//!
//! Configuration (environment):
//! - `KITH_RELAY_ADDR`: listen address, default `0.0.0.0:8080`
//! - `KITH_RELAY_AUTH_TIMEOUT_SECS`: seconds a connection has to authenticate, default `10`
//! - abuse limits (REQ-RELAY-006), see [`Limits::from_env`]
//! - `KITH_RELAY_ALLOWED_ORGS`: org IDs (hex root public keys, separated by commas or
//!   whitespace) this relay serves (REQ-RELAY-008). Unset or empty: every org is served.
//! - `KITH_RELAY_AZURE_STORAGE_ACCOUNT` / `KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING`
//!   (feature `azure-state`): read the approved orgs from an Azure Table instead, re-read
//!   every `KITH_RELAY_ALLOWLIST_REFRESH_SECS` (default 30). See [`state`].
//! - `KITH_RELAY_OPEN_ORGS=true`: serve every org even with the Azure state; the list is not read
//!   (REQ-RELAY-009). Not combinable with `KITH_RELAY_ALLOWED_ORGS`.
//! - `KITH_RELAY_PERSIST_REVOCATIONS=true` (with the Azure state): keep revocation notices in a table
//!   and reload them at start (ADR 0014).
//! - `RUST_LOG`: log filter, default `info`
//!
//! Connection: `hello` -> relay `challenge` -> `auth` (signature over
//! [`kith_protocol::auth_message`]). Every other frame is refused until the device
//! has proven it owns its key. Then `announce` lists orgs with membership proofs
//! (certificate chains, ADR 0005), checked against the org ID, which is the org's
//! root public key (REQ-RELAY-004). A device announcing an org without a proof is
//! *pending*: it may only send `invite-claim` (routed to the org's online admins,
//! or the named member, as `claim-deliver`) and receive `direct` messages. Revoked
//! devices can't be pending. Org IDs are compared in canonical (lower-case) form.
//! Revocation notices count only from an admin's announce; removing an admin needs
//! a root-signed notice, and an admin the root removed revokes nobody (ADR 0018).
//! Outboxes, idle connections, connections per address and relay state are
//! bounded (ADR 0019).

pub mod state;

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Extension, Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use kith_core::membership::{CertChain, Revocation};
use kith_core::{DeviceId, verify_signature};
use kith_protocol::{
    Frame, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, auth_message, decode, encode, supports_version,
};
use kith_relay::{Role, Route, RoutingTable};
use tokio::sync::{Notify, mpsc};

mod connection;
mod limits;
mod outbox;
mod revocation;
mod routing;
mod session;
mod shared;

pub use connection::app;
pub use limits::Limits;
pub use shared::{Relay, Shared, new_state, new_state_with, parse_allowed_orgs, set_allowed_orgs};

#[cfg(test)]
use connection::*;
use limits::*;
use outbox::*;
use revocation::*;
use routing::*;
use session::*;
use shared::*;

#[cfg(test)]
mod tests;
