# PAAS server
The PAAS server provides a REST API to transcrypt pseudonyms between different domains.
It wraps around the `libpep` library, which provides homomorphic pseudonymization.
Moreover, it performs access control on whether pseudonymization is allowed between certain domains.

The server is built in Rust, using the `actix-web` framework.
Sessions can be stored in memory or in a Redis database.
User authentication is done using JWT tokens (but can be easily extended to other methods), that are expected to be passed in the `Authorization` header as a Bearer token.
The JWTs should contain the `sub` field, which is used to identify the user, and a `groups` field, which is used to identify the user's roles.
Access rules are loaded from a yml file, describing which groups are allowed to pseudonymize between which domains.
The expected signing key is read from a file.

## Docker build
A Dockerfile is provided to build a server image.
Notice that the server build requires building the whole cargo workspace.
Therefore, you should build the Docker image from the **root of the repository**, specifying the `-f server/Dockerfile`.

```bash
docker build -t paas-server -f server/Dockerfile .
```
