# PaaS - Pseudonymization as a Service

This is the PaaS pseudonymization service. It is a REST API around [`libpep`](https://github.com/JobDoesburg/libpep) for homomorphic pseudonymization.
Using multiple PaaS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.
