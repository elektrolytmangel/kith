# Platform, packaging and integration

### REQ-PLAT-001: One shared Rust core

- **Priority:** must | **Phase:** 1 | **Status:** implemented | **Verify:** review | **Source:** design §Technology stack

All protocol logic (validation, merge, sync) must live in the Rust crates;
bindings only convert types.

### REQ-PLAT-002: Swift and Kotlin bindings

- **Priority:** must | **Phase:** 1 | **Status:** partial | **Verify:** test | **Source:** design §Technology stack

The library must be usable from Swift (iOS/macOS, Swift Package) and Kotlin
(Android AAR) via UniFFI.

### REQ-PLAT-003: Web bindings

- **Priority:** must | **Phase:** 1 | **Status:** partial | **Verify:** test | **Source:** design §Technology stack

The library must be usable from JavaScript/TypeScript via WebAssembly,
published as an npm package.

### REQ-PLAT-004: Relay as container image

- **Priority:** must | **Phase:** 2 | **Status:** partial | **Verify:** manual | **Source:** this repo

The relay must ship as a container image that runs with a read-only root
filesystem.

### REQ-PLAT-005: Automated, versioned releases

- **Priority:** must | **Phase:** 1 | **Status:** partial | **Verify:** review | **Source:** this repo

A tag `vX.Y.Z` must build and publish all artifacts (crates, npm, Swift,
Android, relay image and binaries) with the same version.

### REQ-PLAT-006: One owner per web database

- **Priority:** must | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** this repo

`KithClient.open` must give a browser database to one client at a time (an exclusive
Web Lock), because each client keeps the MLS group state in memory and a second one
on the same database would overwrite it and could reuse encryption keys. A second
tab gets a clear error, or can wait until the first is gone.

### REQ-PLAT-007: Web connection recovers by itself

- **Priority:** must | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** this repo

A web relay connection that drops must reconnect with backoff (and at once when the
browser comes back online) until the app disconnects, and tell the app with
`reconnecting` and `connected` events. Changes made while offline stay stored and
are exchanged by catch-up.

### REQ-PLAT-008: Web key and storage helpers

- **Priority:** should | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** this repo

The npm package must offer a way to keep the device key encrypted at rest with a
non-extractable key, to request persistent storage and to read the storage quota.

### REQ-PLAT-009: Web package runs under a strict CSP

- **Priority:** should | **Phase:** 8 | **Status:** implemented | **Verify:** test | **Source:** this repo

The npm package must work with a Content-Security-Policy that allows only
`'self'` and `'wasm-unsafe-eval'` for scripts (no `'unsafe-eval'`, no inline scripts).
