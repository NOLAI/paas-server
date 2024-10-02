# Rust REST API

This is a basic REST API service implemented in Rust using the `actix-web` framework. It includes token-based authentication for securing endpoints.

## Prerequisites

- Rust (https://www.rust-lang.org/tools/install)

## Setup

1. Clone the repository:
    ```sh
    git clone <repository-url>
    cd rust_rest_api
    ```

2. Build the project:
    ```sh
    cargo build
    ```

3. Run the project:
    ```sh
    cargo run
    ```

## Example

```sh
cd example & npm run example
```

## Endpoints

### GET /item

Returns a JSON object.

- **URL:** `/item`
- **Method:** `GET`
- **Auth required:** Yes
- **Headers:**
  - `Authorization: Bearer mysecrettoken`

### POST /item

Creates a new item.

- **URL:** `/item`
- **Method:** `POST`
- **Auth required:** Yes
- **Headers:**
  - `Authorization: Bearer mysecrettoken`
- **Body:**
  ```json
  {
    "name": "item_name"
  }
  ```

## License

This project is licensed under the MIT License.
