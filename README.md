# private-key-service

This project implements a simple web service in Rust that proves ownership of a private key using RSA Pkcs8 signatures. It includes two components:

- **Verifier**: A web API that issues nonces and verifies signed payloads.
- **Holder** (script): Signs messages with a private key and proves ownership by sending them to the verifier.

---

## Requirements

- [Rust (stable)](https://www.rust-lang.org/tools/install)
- `cargo` (comes with Rust)

---

## Running the Verifier API

1. **Clone the project**

```bash
git clone https://github.com/andyjohnson70/private-key-service.git
```

2. **Install dependencies**

```bash
cargo build
```

3. **Generate key pair**

```bash
cargo run --bin generate_keys
```
This creates:

private_key.pem — text file containing the Pkcs8 private key

public_key.pem — text file containing the Pkcs8 public key

4. **Run the verifier**

```bash
cargo run --bin verifier
```

You should see:

```
Listening on http://localhost/7878...
```

---

## Running the Holder script

1. **Run the holder script in a separate shell instance**

```bash
cargo run --bin holder
```

You should see:

```
Verify response: 200 OK
```

This confirms that the payload was signed by the corresponding private key and is owned by the holding script.

## How It Works
1. The holder script requests a nonce from GET /nonce.

2. It creates a message like message:nonce, signs it with a private key, and base64 encodes the signature.

3. It sends a POST /verify with:

``` json
{
  "message": "hello world",
  "nonce": "<nonce from verifier>",
  "signature": "<base64-encoded signature>"
}
```
The verifier:

1. Validates that the nonce is unused

2. Verifies the signature using public_key.pem

3. Returns 200 OK if valid, or 401 Unauthorized if not
