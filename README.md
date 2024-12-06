# PaaS - Pseudonymization as a Service

This is the PaaS pseudonymization service. It is a REST API around [`libpep`](https://github.com/JobDoesburg/libpep) for homomorphic pseudonymization.
Using multiple PaaS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

# Setup
## Requirements
- Docker (Get started [here](https://docs.docker.com/get-docker/))
- Docker-compose (Get started [here](https://docs.docker.com/compose/install/))
- Rust (Get started [here](https://www.rust-lang.org/tools/install))

## Running the service
1. Clone the repository
2. Edit the files in resources/ to your liking
3. ```cargo build --release``` or ```cargo build``` if you don't want to build the release version

# JS/TS client
A JS/TS client is available [here](https://www.npmjs.com/package/@nolai/paas-client)

To install it, run:

```npm install @nolai/paas-client @nolai/libpep-wasm``` 

or 

```yarn add @nolai/paas-client @nolai/libpep-wasm```

```typescript
let encrypted_pseudonym = {
    encrypted,
    orginalEncryptSession
} // This is the encrypted pseudonym you want to pseudonymize

const config: PseudonymServiceConfig = {
    blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "BLINDED_GLOBAL_PRIVATE_HEX_KEY",
    ),
    globalPublicKey: new GlobalPublicKey(),
    transcryptors: [
        new PEPTranscryptor("TRANSCRYPTOR_URL_1", "SECRET_TOKEN_1"),
        new PEPTranscryptor("TRANSCRYPTOR_URL_2", "SECRET_TOKEN_2"),
        new PEPTranscryptor("TRANSCRYPTOR_URL_3", "SECRET_TOKEN_3"),
    ],
};

const pseudonymService = new PseudonymService(config, "DOMAIN_1", false);

const resultRandom = await pseudonymService.pseudonymize(
    encrypted_pseudonym.encrypted,
    "DOMAIN_2",
    encrypted_pseudonym.orginalEncryptSession,
    "random",
);
```