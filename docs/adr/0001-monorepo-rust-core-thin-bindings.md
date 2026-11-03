# 0001: Monorepo with a Rust core and thin bindings

- **Status:** accepted
- **Date:** 2026-11-03
- **Requirements:** REQ-PLAT-001, REQ-PLAT-002, REQ-PLAT-003, REQ-STORE-002

## Context

Every client must validate, merge and sync identically, or organizations
diverge. The library must run on web, iOS, Android and desktop, and the relay
must be deployable on its own.

## Decision

- One Cargo workspace contains all protocol logic, split into small crates by
  responsibility (`core`, `protocol`, `crypto`, `store`, `sync`, `client`, `relay`).
- Platform packages are generated from it: UniFFI for Swift and Kotlin,
  wasm-bindgen for JS. Binding crates only convert types.
- The relay is a library (`kith-relay`, no I/O) plus a thin server binary,
  so it can be embedded or run as a container.
- Storage, signing, transport and group crypto sit behind traits, so apps
  can adapt them without forking.
- Everything is versioned and released together from one tag.

## Consequences

- One place to fix bugs; all platforms get them in the same release.
- Mobile and web packages need native toolchains in CI (macOS runner, NDK).
- A breaking protocol change touches every package at once. That's intended,
  and the shared version makes it visible.

## Alternatives considered

- Separate repositories per platform: duplicated logic and drifting versions.
- Native reimplementations per platform: the divergence risk the design warns against.
