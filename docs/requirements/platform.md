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
