FROM rust:slim-bookworm AS chef
LABEL authors=["Julian van der Horst"]
RUN cargo install cargo-chef
WORKDIR /paas_server

FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev
WORKDIR /paas_server
COPY --from=planner /paas_server/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

# build for release
RUN cargo fetch
RUN cargo build --release

# our final base
FROM debian:bookworm-slim

EXPOSE 8080

RUN apt-get update && apt-get install -y netcat-openbsd curl
# copy the build artifact from the build stage
COPY --from=builder /paas_server/target/release/paas_server .

COPY ./resources/entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


