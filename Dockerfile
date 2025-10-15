FROM rust:slim-bookworm AS chef
LABEL authors=["Julian van der Horst"]
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-chef
WORKDIR /paas_server

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev
WORKDIR /paas_server
COPY --from=planner /paas_server/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/paas_server/target \
    cargo chef cook --release --recipe-path recipe.json

COPY . .

# build for release
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/paas_server/target \
    cargo build --release && \
    cp /paas_server/target/release/paas_server /tmp/paas_server

# our final base
FROM debian:bookworm-slim

EXPOSE 8080

RUN apt-get update && apt-get install -y netcat-openbsd curl
# copy the build artifact from the build stage
COPY --from=builder /tmp/paas_server .

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

HEALTHCHECK --start-period=30s --interval=30s --timeout=3s --retries=3 \
  CMD curl -f http://0.0.0.0:8080/health || exit 1
