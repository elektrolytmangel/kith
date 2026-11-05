# 0020: Checked Automerge changes

- **Status:** accepted
- **Date:** 2026-11-05
- **Requirements:** REQ-DATA-004, REQ-STORE-001
- **Amends:** [ADR 0003](0003-merge-automerge-default-pluggable.md)

## Context

Payloads come from other devices, and the Automerge library expects changes that a correct
Automerge client produced. `materialize` runs on every read, so whatever it accepts must keep
the document readable for every member, and every member must reach the same result.

## Decision

- **Checked before applied.** `AutomergeMerger` walks the changes in causal order (ties by
  hash) and checks each one against its own history: every operation refers to the root or to
  objects, list elements and earlier operations the change has seen, list keys are used only in
  lists and text, map keys only in maps, and an actor's changes form a chain. A change that fails,
  and every change built on it, is reported in `skipped` and left out. The result depends only on
  the set of changes. Where panics unwind, a failure inside Automerge is caught as well and that
  change is left out.
- **Bounded nesting.** Objects nest at most `MAX_DEPTH` (100) deep. Deeper changes are skipped,
  `to_json` reads anything deeper as `null`, and `merge_patch` refuses deeper patches.
- **Bounded size.** A payload must be one change chunk, at most `MAX_CHANGE_BYTES` (8 MiB) after
  decompression; a compressed chunk is checked with a bounded inflate before Automerge parses it.
- **Parents stay in their object.** A received change whose known parent belongs to another
  object is refused, and the SQLite store's heads count only children in the same object, like
  the other stores.

## Consequences

- `materialize` decodes each change once more for the checks.
- Documents deeper than 100 levels are not supported.
