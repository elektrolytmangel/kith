# Sync

### REQ-SYNC-001: Catch-up from one online peer

- **Priority:** must | **Phase:** 3 | **Status:** partial | **Verify:** test | **Source:** design §Catch-up

A returning client must be able to catch up from any one online member; the
relay must prefer always-on clients as sync partners.

### REQ-SYNC-002: Exchange only missing changes

- **Priority:** must | **Phase:** 3 | **Status:** partial | **Verify:** test | **Source:** design §Catch-up

Catch-up must reconcile sets of change IDs and transfer only missing changes,
in both directions.

### REQ-SYNC-003: Join from empty

- **Priority:** must | **Phase:** 3 | **Status:** partial | **Verify:** test | **Source:** design §Joining

A new device must receive the full history through the same catch-up path,
starting from an empty store.

### REQ-SYNC-004: Live updates

- **Priority:** must | **Phase:** 2 | **Status:** partial | **Verify:** test | **Source:** design §Live updates

While online, a client must broadcast each new change; receivers must
validate before storing.

Done for native Rust: `kith_net::LiveClient` broadcasts via the relay and
`Client::handle_frame` validates and stores (bad changes are reported as
`Event::Rejected`). Open: the browser WebSocket client, exposing it in the Swift/Kotlin/JS
bindings, and encrypting the bodies (phase 4: they are plaintext on the relay today).

### REQ-SYNC-005: Resumable large syncs

- **Priority:** should | **Phase:** 7 | **Status:** proposed | **Verify:** test | **Source:** design §Large syncs

Large initial syncs should be chunked and resumable, preferring a direct
peer-to-peer connection.
