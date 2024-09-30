FROM rust:slim-buster AS build
LABEL authors=["Julian van der Horst"]

WORKDIR /pep_api_service

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Build and cache the dependencies
RUN rm -rf src
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
RUN cargo build --release
RUN rm src/main.rs

# copy your source tree
COPY ./src src

# build for release
RUN cargo build --release

# our final base
FROM debian:buster-slim

EXPOSE 8080

RUN apt-get update && apt-get install -y netcat-openbsd curl
# copy the build artifact from the build stage
COPY --from=build /pep_api_service/target/release/pep_api_service .

COPY ./resources/entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


