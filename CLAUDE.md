# CLAUDE.md

kith: local-first, end-to-end encrypted sync library (Rust core, bindings for
web, Swift, Kotlin) plus a generic relay. Start with [README.md](README.md).

## Always: keep PLAN.md current

[PLAN.md](PLAN.md) is the handover document between sessions.

- **At the start of a session:** read `PLAN.md` before doing anything else.
- **Whenever you make a plan** (next steps, a multi-step task, a proposal to the
  user): write it into `PLAN.md` (*Plan* / *Next steps*, *Open questions*), not
  only in chat.
- **Whenever you finish or stop work:** update `PLAN.md` in the same change:
  check off done items, update *Where things stand*, add new decisions,
  pitfalls and open issues, add a dated line to *Log*, set *Last updated*.
- Record user decisions under *Decisions* so later sessions don't re-ask them.
- Keep it short and current: replace stale text instead of appending history.

## How to work here

- Workflow, local commands (Docker, no local Rust toolchain): [docs/guides/development.md](docs/guides/development.md).
- Requirements: `docs/requirements/`; tag tests `/// req: REQ-…`; run `python3 scripts/reqs.py --write`.
- Releases: [docs/guides/releasing.md](docs/guides/releasing.md).
- Branch + PR for every change; the user merges.
