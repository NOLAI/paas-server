# PAAS server
[![Crates.io](https://img.shields.io/crates/v/paas-server.svg)](https://crates.io/crates/paas-server)
[![Downloads](https://img.shields.io/crates/d/paas-server.svg)](https://crates.io/crates/paas-server)
[![License](https://img.shields.io/crates/l/paas-server.svg)](https://crates.io/crates/paas-server)
[![Documentation](https://docs.rs/paas-server/badge.svg)](https://docs.rs/paas-server)
[![Dependencies](https://deps.rs/repo/github/NOLAI/paas-server/status.svg)](https://deps.rs/repo/github/NOLAI/paas-server)

This project contains the server implementation for PAAS, the PEP Authorisation API Service (or _Pseudonymization as a Service_).

The PAAS server provides a REST API to transcrypt pseudonyms between different domains.
It wraps around the [`libpep` library](https://crates.io/crates/libpep), which provides homomorphic pseudonymization.
Moreover, it performs access control on whether pseudonymization is allowed between certain domains.

The server is built in Rust, using the `actix-web` framework.
Sessions can be stored in memory or in a Redis database.
User authentication is done using JWT tokens (but can be easily extended to other methods), that are expected to be passed in the `Authorization` header as a Bearer token.
The JWTs should contain the `sub` field, which is used to identify the user, and a `groups` field, which is used to identify the user's roles.
Access rules are loaded from a yml file, describing which groups are allowed to pseudonymize between which domains.
The expected signing key is read from a file.

## Docker build
A Dockerfile is provided to build a server image.

```bash
docker build -t paas-server
```
