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
   - checks that the tag matches `Cargo.toml` and that requirements pass,
   - pushes `ghcr.io/OWNER/kith-relay:{0.2.0,0.2}` for amd64 and arm64,
   - builds relay binaries for Linux, macOS and Windows,
   - publishes the npm package,
   - builds and tests the XCFramework and optionally pushes the Swift package mirror,
   - builds and publishes the Android AAR,
   - publishes crates to crates.io, only if `PUBLISH_CRATES=true`,
   - creates the GitHub Release with all artifacts and generated notes.

To build everything without publishing, run the workflow manually under
*Actions → Release → Run workflow* with `dry_run` checked (the default). All
packages are attached to the run as artifacts. Unticking `dry_run` publishes,
but only when the workflow is run on a `vX.Y.Z` tag.

If a release fails halfway, use *Re-run failed jobs* on the original run. A
fresh run would fail on the packages that were already published, because npm
and Maven reject an existing version.

## Configuration

Set repository variables and secrets as listed at the top of
`release.yml`. By default, everything publishes to this repository's GitHub
Packages and Releases using `GITHUB_TOKEN`, so nothing is public until you
choose a public registry.

### Private repositories

- `relay-binaries` uses the `ubuntu-24.04-arm` runner. If it isn't available
  for your plan, remove that matrix entry or switch it to `ubuntu-latest` with
  [`cross`](https://github.com/cross-rs/cross).
- Swift Package Manager downloads `KithFFI.xcframework.zip` from the release
  without credentials. For private repositories, use a public mirror
  (`SWIFT_PACKAGE_REPO`) or configure `.netrc` for consumers.
- macOS runner minutes count 10× for private repositories. The Swift job runs
  only in the Release workflow, not on every PR.

## Versioning policy

Follow SemVer. While below 1.0, a minor bump may break the API. Changes to the
wire protocol or the change envelope always need an ADR and a minor bump,
plus a `PROTOCOL_VERSION` bump when old and new clients can't talk to each other.
