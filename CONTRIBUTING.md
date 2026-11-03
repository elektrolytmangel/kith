# Contributing

1. Find or write the requirement your change serves (`docs/requirements/`).
   If none exists, open a *Requirement* issue first.
2. Branch from `main`, implement, and add tests tagged `/// req: REQ-…`.
3. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`
   and `python3 scripts/reqs.py --write`.
4. Open a PR and fill in the template. Changes to the protocol, envelope or
   crypto need an ADR (`docs/adr/`) and review by a CODEOWNER.

More: [development guide](docs/guides/development.md), [releasing](docs/guides/releasing.md).
