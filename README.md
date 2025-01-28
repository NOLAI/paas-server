# PAAS - PEP Authorisation API Service / Pseudonymization as a Service

This is the PAAS pseudonymization service. It is a REST API around [`libpep`](https://github.com/JobDoesburg/libpep) for homomorphic pseudonymization.
It's name stands for PEP Authorisation API Service, but it is also a play on words with the term "Pseudonymization as a Service".

Using multiple PAAS transcryptors, it is possible to blindly convert encrypted pseudonyms, encrypted by clients, into different encrypted pseudonyms for different clients, in a distributed manner.
As long as 1 transcryptor is not compromised, the pseudonymization is secure, meaning that nobody can link pseudonyms of different clients together.

Each transcryptor is able to enforce access control policies, such as only allowing pseudonymization for certain domains or contexts.
This way, using PAAS, you can enforce central monitoring and control over unlinkable data processing in different domains or contexts.

# Setup
## Requirements
- Docker (Get started [here](https://docs.docker.com/get-docker/))
- Docker-compose (Get started [here](https://docs.docker.com/compose/install/))
- Rust (Get started [here](https://www.rust-lang.org/tools/install))

## Docker build
Notice that the server Docker build requires building the whole workspace.
Therefore, you should build the Docker image from the root of the repository, specifying the `-f server/Dockerfile`.
    
```bash
docker build -t paas-server -f server/Dockerfile .
```

# JS/TS client
A JS/TS client is available [here](https://www.npmjs.com/package/@nolai/paas-client)

To install it, run:

```npm install @nolai/paas-client @nolai/libpep-wasm``` 

or 

```yarn add @nolai/paas-client @nolai/libpep-wasm```

Use the client as follows

```typescript
const config: PseudonymServiceConfig = {
    blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "dacec694506fa1c1ab562059174b022151acab4594723614811eaaa93a9c5908",
    ),
    globalPublicKey: GlobalPublicKey.fromHex(
        "3025b1584bc729154f33071f73bb9499509bb504f887496ba86cb57e88d5dc62",
    ),
    transcryptors: [
        new TranscryptorConfig("test_system_1", "http://localhost:8080"),
        new TranscryptorConfig("test_system_2", "http://localhost:8081"),
    ],
};

const authTokens = new Map(
    [["test_system_1", "test_token_1"], ["test_system_2", "test_token_2"],],
)

const encryptedPseudonym = EncryptedPseudonym.fromBase64(
    "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==",
);
const sessions = new Map(
    [["test_system_1", "session_1"], ["test_system_2", "session_2"],],
);
const domainFrom = "domain1";
const domainTo = "domain2";

const service = new PseudonymService(config, authTokens);
const result = await service.pseudonymize(
    encryptedPseudonym,
    sessions,
    domainFrom,
    domainTo,
);
const pseudonym = await service.decryptPseudonym(result);
console.log(pseudonym.asHex()) 
```