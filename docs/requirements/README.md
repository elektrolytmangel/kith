# Requirements

Requirements are plain Markdown, versioned with the code, reviewed in PRs,
and traced to tests automatically.

## Files

| File | Prefix | Area |
| --- | --- | --- |
| [identity-encryption.md](identity-encryption.md) | `ID`, `ENC` | Device keys, MLS groups |
| [data.md](data.md) | `DATA`, `STORE` | Change envelope, history, concurrency, local storage |
| [relay.md](relay.md) | `RELAY` | Routing server |
| [sync.md](sync.md) | `SYNC` | Live updates, catch-up, joining |
| [invitations.md](invitations.md) | `INV` | Onboarding and device removal |
| [permissions.md](permissions.md) | `PERM` | Policy object, validation |
| [files.md](files.md) | `FILE` | Large encrypted blobs |
| [platform.md](platform.md) | `PLAT` | Bindings, packaging, compatibility |
| [TRACEABILITY.md](TRACEABILITY.md) | | **Generated.** Requirement → code/test matrix |

## Format

Each requirement is a level-3 heading with a stable ID, followed by one
metadata line and the text:

```markdown
### REQ-RELAY-001: Relay persists nothing

- **Priority:** must | **Phase:** 2 | **Status:** partial | **Verify:** test | **Source:** design §Relay

The relay writes no message content, metadata or keys to disk. ...
```

| Field | Values |
| --- | --- |
| Priority | `must`, `should`, `could` |
| Phase | implementation phase from the design doc (1–8) |
| Status | `proposed` → `accepted` → `partial` → `implemented` → `verified`; or `deferred`, `rejected` |
| Verify | `test` (automated), `review` (code/security review), `manual` (documented procedure) |
| Source | where it came from: design doc section, issue `#123`, customer, ADR |

Rules:

- IDs are never reused or renumbered. Retire a requirement by setting `rejected`.
- Use "must/should" wording in the text; one testable statement per requirement.
- Decisions *about* requirements (trade-offs, open questions answered) go in
  [`docs/adr/`](../adr/), linked from the requirement's Source.

## Tracing to code

Reference a requirement in a doc comment or comment next to the test that
verifies it:

```rust
/// req: REQ-RELAY-001
#[test]
fn disconnect_forgets_everything() { ... }
```

Production code may reference IDs too (e.g. `TODO(REQ-RELAY-004)`).

`scripts/reqs.py` checks, locally and in CI:

1. IDs are unique and well-formed; metadata values are valid.
2. Every `REQ-…` reference in code points to an existing requirement.
3. Every `implemented`/`verified` requirement with `Verify: test` has at least
   one reference from a test.
4. `TRACEABILITY.md` is up to date.

```sh
python3 scripts/reqs.py            # check
python3 scripts/reqs.py --write    # regenerate TRACEABILITY.md
```

## Workflow

1. New need → open a **Requirement** issue (template provided) or a PR that
   adds the requirement with `Status: proposed`.
2. Review and accept → `accepted`.
3. Implementation PRs list the IDs they address (PR template) and move the
   status to `partial` / `implemented`, with tests tagged `req: …`.
4. Release checklist: every `must` for the release's phase is `implemented`.
