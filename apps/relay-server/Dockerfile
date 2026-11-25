# Build from the repository root:
#   docker build -f apps/relay-server/Dockerfile -t kith-relay .
FROM rust:1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
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
