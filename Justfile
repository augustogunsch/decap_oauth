docker-image := "ghcr.io/somniumensemble/decap_oauth"
docker-tag := "v0.0.3"

default:
    @just --list

fmt:
    cargo fmt

lint:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

test:
    cargo test

check: lint test

docker-build:
    docker build \
        -t {{ docker-image }}:{{ docker-tag }} \
        .

docker-push:
    docker push {{ docker-image }}:{{ docker-tag }}

start:
    docker run --rm -d \
        -p $DECAP_OAUTH_PORT:3005 \
        -e OAUTH_CLIENT_ID=$OAUTH_CLIENT_ID \
        -e OAUTH_SECRET=$OAUTH_SECRET \
        -e OAUTH_ORIGINS=$OAUTH_ORIGINS \
        {{ docker-image }}:{{ docker-tag }}
