FROM rust:1.95 AS builder
WORKDIR /usr/src/app
COPY . .
RUN cargo install --path .

FROM debian:trixie-slim
RUN apt update && apt install -y ca-certificates
COPY --from=builder /usr/local/cargo/bin/decap_oauth /usr/bin/decap_oauth

CMD ["decap_oauth"]
