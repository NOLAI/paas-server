# PAAS-client Pseudonym Service
The PAAS client is a library to interact with PAAS servers or transcryptors, wrapping around `libpep` (and `libpep-wasm`).
It is available in Rust and JS/TS.
For the Rust client, there is also a `paascli` binary available.

## Installation 
The JS/TS client is available [here](https://www.npmjs.com/package/@nolai/paas-client)

To install it, run:

```npm install @nolai/paas-client @nolai/libpep-wasm```

or

```yarn add @nolai/paas-client @nolai/libpep-wasm```

> [!CAUTION]
> Make sure to allways have the same `@nolai/libpep-wasm` version as `@nolai/paas-client`. Some bundlers could download the other version and paas-client would be not using the same wasm file that you use in other parts of your project

The Rust client is available [here](https://crates.io/crates/paas-client)

To install it, run:

```cargo install paas-client```

## Usage
We provide a simple example of how to use the client, in typescript.
The usage is similar in Rust.

```typescript
import {EncryptionContexts} from "./sessions";

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

const authTokens = new new Map(
    [["test_system_1", "test_token_1"], ["test_system_2", "test_token_2"],],
)

const encryptedPseudonym = EncryptedPseudonym.fromBase64(
    "nr3FRadpFFGCFksYgrloo5J2V9j7JJWcUeiNBna66y78lwMia2-l8He4FfJPoAjuHCpH-8B0EThBr8DS3glHJw==",
);

const sessions = new EncryptionContexts( 
    new Map(
        [
            ["test_system_1", "session_1"], 
            ["test_system_2", "session_2"],
        ],
));

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

The rust binary `paascli` is available to interact with the PAAS server.
For example run the following command to pseudonymize an encrypted pseudonym from domain1 to domain2:
```bash
paascli --config config.json --tokens tokens.json --state state.json pseudonymize CvkMpV4E98A1kWReUi0dE4mGRm1ToAj_D5-FrSi1FBqCrqE6d5HNrV8JW6vsGkwputG2S821sfjzjsyFGUPzAg== eyJQYWFTLWRlbW8tMyI6InVzZXIxXzB4T0VpZXBPTjAiLCJQYWFTLWRlbW8tMSI6InVzZXIxXzhGZmhDQU5WVmIiLCJQYWFTLWRlbW8tMiI6InVzZXIxX2tibk5UUVZpYjkifQ== domain1 domain2
```

Or during development, you can run:
```bash
cargo run --bin paascli -- --config config.json --tokens tokens.json --state state.json pseudonymize CvkMpV4E98A1kWReUi0dE4mGRm1ToAj_D5-FrSi1FBqCrqE6d5HNrV8JW6vsGkwputG2S821sfjzjsyFGUPzAg== eyJQYWFTLWRlbW8tMyI6InVzZXIxXzB4T0VpZXBPTjAiLCJQYWFTLWRlbW8tMSI6InVzZXIxXzhGZmhDQU5WVmIiLCJQYWFTLWRlbW8tMiI6InVzZXIxX2tibk5UUVZpYjkifQ== domain1 domain2
```

