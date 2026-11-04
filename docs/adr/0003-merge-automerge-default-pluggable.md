# 0003: Automerge by default, merge strategy pluggable per type

- **Status:** accepted
- **Date:** 2026-11-04
- **Requirements:** REQ-DATA-004 (also REQ-DATA-002)

## Context

Concurrent edits fork an object's change graph (two heads). Every client must
resolve the fork to the same state without locks. The design doc left open
whether all types are Automerge documents or some use detect-and-resolve.
REQ-DATA-002 says the core never interprets payloads.

## Decision

- The core stays payload-agnostic. A `Merger` (crate `kith-merge`) turns an
  object's full history into one state; the same set of changes gives the same
  state on every client, independent of arrival order.
- **Default merger: Automerge.** A change's payload is one Automerge change; the
  state is an Automerge document. Apps use it for JSON-like data.
- Other types implement `Merger` themselves (last-writer-wins, detect-and-resolve)
  or have none and stay forked until the app resolves them.
- Changes whose payload a merger cannot decode are skipped and reported in
  `Materialized::skipped`; they stay in the append-only history.
- A write after a fork names all heads as parents, which joins the fork in the
  kith graph (the CRDT already merged the content).
- Automerge is opt-in per crate (`kith-merge/automerge`, `kith-client/automerge`)
  because it is large on wasm. `kith-merge` builds for wasm32.
- The workspace MSRV is **1.90**, because `automerge` 0.12 requires it
  (0.7.x does not compile against current dependencies without a lockfile pin).

## Consequences

- Apps get conflict-free merging for documents without the core knowing the format.
- Permission checks stay outside the merge (validate before applying).
- Merge is not yet exposed in the Swift/Kotlin/JS bindings.
- Raising the MSRV is a cost for users of the Rust crates on older toolchains.

## Alternatives considered

- Automerge for every type: breaks REQ-DATA-002 and locks all apps into Automerge.
- Detect-and-resolve only: no new dependency, but every app reimplements merging.
