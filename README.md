# PAAS - PEP Authorisation API Service / Pseudonymization as a Service

This is the PAAS pseudonymization service. It is a REST API around [`libpep`](https://github.com/JobDoesburg/libpep) for homomorphic pseudonymization.
It's name stands for PEP Authorisation API Service, but it is also a play on words with the term "Pseudonymization as a Service".

Using multiple PAAS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

Each transcryptor is able to enforce access control policies, such as only allowing pseudonymization for certain domains or contexts.
This way, using PAAS, you can enforce central monitoring and control over unlinkable data processing in different domains or contexts.

Inspect the [client](client/README.md) and [server](server/README.md) READMEs for more information.
