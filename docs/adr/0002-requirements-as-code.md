# 0002: Requirements as code with automated traceability

- **Status:** accepted
- **Date:** 2026-11-03
- **Requirements:** all

## Context

The system has security-relevant requirements (no persistence on the relay,
validation of every change). We need to see which are implemented and tested,
without a separate tool that drifts from the code.

## Decision

Requirements live as Markdown in `docs/requirements/` with stable IDs and a
metadata line. Tests reference IDs (`req: REQ-…`). `scripts/reqs.py`
validates IDs and references and generates `TRACEABILITY.md`. CI fails on
unknown IDs, untested "implemented" requirements, or a stale matrix.

## Consequences

- Requirement changes are reviewed in PRs like code.
- Status is visible on GitHub and in each CI run's summary.
- The process depends on people tagging tests. Review checks this through the
  PR template.

## Alternatives considered

- Issue tracker only: not versioned with code, so no link to tests.
- Dedicated requirements tool: extra licence and sync effort for a small team.
