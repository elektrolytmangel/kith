# Build from the repository root:
#   docker build -f apps/relay-server/Dockerfile -t kith-relay .
FROM rust:1-bookworm@sha256:7085845219c18e7c5b1f34ed9ce89b84f822f2e3d54a02774cedc996ac0f304f AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p kith-relay-server --features azure-state

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/kith-relay /kith-relay
ENV KITH_RELAY_ADDR=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
# Read-only root filesystem friendly: the relay writes nothing to disk.
# The build includes the optional Azure Table state (KITH_RELAY_AZURE_STORAGE_*).
USER nonroot
ENTRYPOINT ["/kith-relay"]
