FROM rust:1.79.0 AS builder
WORKDIR /app
RUN apt-get update
RUN apt-get install -y musl-tools
RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new decap_oauth
WORKDIR /app/decap_auth

COPY src ./src

COPY Cargo.toml Cargo.lock ./
RUN cargo install --locked --target x86_64-unknown-linux-musl --path .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/local/cargo/bin/decap_oauth .
USER 1000
CMD ["./decap_oauth"]
