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
   - builds the relay and always-on client binaries for Linux, macOS and Windows,
   - builds the npm package and smoke-tests it in Node,
   - builds the XCFramework, tests the Swift package against it and packages it,
   - builds the Android AAR,
   - builds the relay and always-on container images and pushes them to ghcr.io (`docker/Dockerfile`),
   - creates the GitHub Release with all of them, `SHA256SUMS`, an SPDX SBOM (`kith-<version>.spdx.json`)
     and generated notes,
   - signs a build provenance attestation for every release file and both images (Sigstore, stored on GitHub
     and, for the images, in ghcr.io next to them).

   GitHub (the Release and GitHub Packages) is the only publish target. After the first release with
   images, make both packages public once, see [deployment.md](deployment.md#publishing-the-images-maintainers).

To build everything without publishing, run the workflow manually under
*Actions → Release → Run workflow* with `dry_run` checked (the default). All
packages are attached to the run as artifacts. Unticking `dry_run` creates the
release, but only when the workflow is run on a `vX.Y.Z` tag.

The release is created only after every package built. If a build fails, fix
it and use *Re-run failed jobs*, or run the workflow on the tag with `dry_run`
unticked.

## Verifying a release

Anyone can check that a release file or image was built by this repository's release workflow
from a tagged commit (needs the [GitHub CLI](https://cli.github.com/)):

```sh
gh attestation verify kith-relay-x86_64-unknown-linux-gnu.tar.gz --repo <owner>/kith
gh attestation verify oci://ghcr.io/<owner>/kith-relay:<version> --repo <owner>/kith
```

`SHA256SUMS` is attested too. The images also carry BuildKit's own SBOM and provenance
(`docker buildx imagetools inspect ghcr.io/<owner>/kith-relay:<version> --format '{{json .SBOM}}'`).

## Configuration

None is required: the workflow uses `GITHUB_TOKEN`. The optional repository
variable `NPM_SCOPE` sets the npm package name `@<scope>/kith-wasm` (default:
the repository owner).

### If your repository is private

This repository is public, so none of this applies here. For projects started
from this template:

- `relay-binaries` uses the `ubuntu-24.04-arm` runner. If it isn't available
  for your plan, remove that matrix entry or switch it to `ubuntu-latest` with
  [`cross`](https://github.com/cross-rs/cross).
- Release assets of a private repository need authentication to download.
  Swift Package Manager fetches `KithFFI.xcframework.zip` from the release
  URL, so consumers need a `.netrc` entry for `github.com` (or should vendor
  the unzipped framework). The same applies to `npm install <asset URL>`.
- macOS runner minutes count 10× for private repositories, and CI builds the
  Swift package on every PR. Consider limiting the `swift` job in `ci.yml` to
  pushes to `main`.

## Versioning policy

Follow SemVer. While below 1.0, a minor bump may break the API. Changes to the
wire protocol or the change envelope always need an ADR and a minor bump,
plus a `PROTOCOL_VERSION` bump when old and new clients can't talk to each other.
Every persisted or exchanged format carries a version marker and a golden test; see
[ADR 0012](../adr/0012-format-stability.md). Breaks are listed under *Breaking* in the changelog.
