FROM rust:1.99 AS builder
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/app/target/release/decap_oauth /usr/bin/decap_oauth

# The service only needs to accept connections; it never writes to disk.
USER 65534:65534
EXPOSE 3005
CMD ["decap_oauth"]
