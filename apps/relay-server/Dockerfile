# Build from the repository root:
#   docker build -f apps/relay-server/Dockerfile -t kith-relay .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p kith-relay-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/kith-relay /kith-relay
ENV KITH_RELAY_ADDR=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
# Read-only root filesystem friendly: the relay writes nothing to disk.
USER nonroot
ENTRYPOINT ["/kith-relay"]
