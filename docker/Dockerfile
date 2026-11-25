# Release images for the relay and the always-on client. They contain the
# prebuilt release binaries, no compiler. Used by .github/workflows/release.yml.
#
# Build context layout (the workflow creates it from the release artifacts):
#   amd64/kith-relay  amd64/kith-always-on
#   arm64/kith-relay  arm64/kith-always-on
#   data/.keep                      (empty data directory for the always-on client)
#
#   docker buildx build -f docker/Dockerfile --target relay -t kith-relay ctx
#
# To build from source instead: apps/relay-server/Dockerfile.

# Debian 13 (glibc 2.41) matches the glibc the release binaries are built against.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab AS base
ARG TARGETARCH
USER nonroot

FROM base AS relay
COPY --chmod=0755 ${TARGETARCH}/kith-relay /kith-relay
ENV KITH_RELAY_ADDR=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
# The relay writes nothing to disk: run it with a read-only root filesystem.
ENTRYPOINT ["/kith-relay"]

FROM base AS always-on
COPY --chmod=0755 ${TARGETARCH}/kith-always-on /kith-always-on
COPY --chown=65532:65532 data/ /data/
ENV RUST_LOG=info
VOLUME /data
# Add arguments after the image name, e.g. `--join -` on the first run (reads the
# invite link from stdin; run with `-i`).
ENTRYPOINT ["/kith-always-on", "--data", "/data"]
