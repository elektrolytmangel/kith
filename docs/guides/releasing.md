# Releasing

All crates and packages share one version, `[workspace.package].version` in
`Cargo.toml`. The npm package takes its version from it through wasm-pack.
Android receives it as `-Pversion` and Swift through the release tag.

## Steps

1. Update `CHANGELOG.md`: move *Unreleased* to the new version.
2. Bump `version` in `Cargo.toml`, both under `[workspace.package]` and in the
   internal entries of `[workspace.dependencies]`.
3. Check: every `must` requirement planned for this release is `implemented`
   in [TRACEABILITY.md](../requirements/TRACEABILITY.md).
4. Merge to `main`, then tag:
   ```sh
   git tag v0.2.0 && git push origin v0.2.0
   ```
5. `.github/workflows/release.yml` then:
   - checks that the tag matches `Cargo.toml`, that requirements pass and that tests pass,
   - builds relay binaries for Linux, macOS and Windows,
   - builds the npm package and smoke-tests it in Node,
   - builds the XCFramework, tests the Swift package against it and packages it,
   - builds the Android AAR,
   - creates the GitHub Release with all of them, `SHA256SUMS` and generated notes.

   The GitHub Release is the only publish target.

To build everything without publishing, run the workflow manually under
*Actions → Release → Run workflow* with `dry_run` checked (the default). All
packages are attached to the run as artifacts. Unticking `dry_run` creates the
release, but only when the workflow is run on a `vX.Y.Z` tag.

The release is created only after every package built. If a build fails, fix
it and use *Re-run failed jobs*, or run the workflow on the tag with `dry_run`
unticked.

## Configuration

None is required: the workflow uses `GITHUB_TOKEN`. The optional repository
variable `NPM_SCOPE` sets the npm package name `@<scope>/kith-wasm` (default:
the repository owner).

### Private repositories

- `relay-binaries` uses the `ubuntu-24.04-arm` runner. If it isn't available
  for your plan, remove that matrix entry or switch it to `ubuntu-latest` with
  [`cross`](https://github.com/cross-rs/cross).
- Release assets of a private repository need authentication to download.
  Swift Package Manager fetches `KithFFI.xcframework.zip` from the release
  URL, so consumers need a `.netrc` entry for `github.com` (or should vendor
  the unzipped framework). The same applies to `npm install <asset URL>`.
- macOS runner minutes count 10× for private repositories. The Swift job runs
  only in the Release workflow, not on every PR.

## Versioning policy

Follow SemVer. While below 1.0, a minor bump may break the API. Changes to the
wire protocol or the change envelope always need an ADR and a minor bump,
plus a `PROTOCOL_VERSION` bump when old and new clients can't talk to each other.
