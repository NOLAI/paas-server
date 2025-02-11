# PAAS API
[![Crates.io](https://img.shields.io/crates/v/paas-api.svg)](https://crates.io/crates/paas-api)
[![Downloads](https://img.shields.io/crates/d/paas-api.svg)](https://crates.io/crates/paas-api)
[![License](https://img.shields.io/crates/l/paas-api.svg)](https://crates.io/crates/paas-api)
[![Documentation](https://docs.rs/paas-api/badge.svg)](https://docs.rs/paas-api)
[![Dependencies](https://deps.rs/repo/github/NOLAI/paas-api/status.svg)](https://deps.rs/repo/github/NOLAI/paas-api)

This project contains the API specification for PAAS, the PEP Authorisation API Service (or _Pseudonymization as a Service_).
It specifies interaction between [PAAS servers](https://github.com/NOLAI/paas-server) and [PAAS clients](https://github.com/NOLAI/paas-client-rs).

PAAS forms a REST API around [`libpep`](https://github.com/NOLAI/libpep) for homomorphic pseudonymization.
Using multiple PAAS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

Each transcryptor is able to enforce access control policies, such as only allowing pseudonymization for certain domains or contexts.
This way, using PAAS, you can enforce central monitoring and control over unlinkable data processing in different domains or contexts.
