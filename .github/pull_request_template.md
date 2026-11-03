## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Requirements

<!-- IDs this PR implements or changes, e.g. REQ-RELAY-004. "none" for pure refactors/tooling. -->

- 

## Checklist

- [ ] Tests that verify a requirement are tagged `/// req: REQ-…`
- [ ] Requirement `Status` updated, and `python3 scripts/reqs.py --write` run
- [ ] Protocol, change envelope or crypto change → ADR added in `docs/adr/` and `PROTOCOL_VERSION` considered
- [ ] Public API change → exposed in `bindings/ffi` and `bindings/wasm`, docs in `docs/guides/integration.md`
- [ ] `CHANGELOG.md` updated under *Unreleased*
