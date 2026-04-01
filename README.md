# rs-jwt

[![CI](https://github.com/philiprehberger/rs-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-jwt/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-jwt.svg)](https://crates.io/crates/philiprehberger-jwt)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rs-jwt)](https://github.com/philiprehberger/rs-jwt/commits/main)

JSON Web Token encoding, decoding, and validation with HMAC algorithms

## Installation

```toml
[dependencies]
philiprehberger-jwt = "0.1.2"
```

## Usage

```rust
use philiprehberger_jwt::{encode, decode, Algorithm, Claims, RegisteredClaims, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

let claims = Claims {
    registered: RegisteredClaims {
        sub: Some("user-123".into()),
        exp: Some(now + 3600),
        iat: Some(now),
        ..Default::default()
    },
    custom: serde_json::json!({}),
};

let secret = b"my-secret-key";
let token = encode(&claims, secret, Algorithm::HS256).unwrap();

let validation = Validation::default();
let decoded: Claims<serde_json::Value> = decode(&token, secret, &validation).unwrap();
assert_eq!(decoded.registered.sub, Some("user-123".into()));
```

### Custom claims

```rust
use serde::{Serialize, Deserialize};
use philiprehberger_jwt::{encode, decode, Algorithm, Claims, RegisteredClaims, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct MyClaims {
    role: String,
    permissions: Vec<String>,
}

let claims = Claims {
    registered: RegisteredClaims::default(),
    custom: MyClaims {
        role: "admin".into(),
        permissions: vec!["read".into(), "write".into()],
    },
};

let token = encode(&claims, b"secret", Algorithm::HS256).unwrap();
let decoded: Claims<MyClaims> = decode(&token, b"secret", &Validation::default()).unwrap();
assert_eq!(decoded.custom.role, "admin");
```

### Quick encoding with `encode_simple`

```rust
use philiprehberger_jwt::encode_simple;
use serde::Serialize;

#[derive(Serialize)]
struct Payload {
    user_id: u64,
}

let token = encode_simple(&Payload { user_id: 42 }, b"secret").unwrap();
```

### Validation options

```rust
use philiprehberger_jwt::Validation;

let validation = Validation::default()
    .leeway(30)
    .issuer("my-app")
    .audience("my-api")
    .required_claims(vec!["sub".into()]);
```

### Inspect a token header

```rust
use philiprehberger_jwt::{inspect, Algorithm};

let header = inspect(&token).unwrap();
assert_eq!(header.alg, Algorithm::HS256);
```

## API

| Function | Description |
|---|---|
| `encode(claims, secret, algorithm)` | Encode claims into a signed JWT string |
| `decode(token, secret, validation)` | Decode and validate a JWT, returning typed claims |
| `encode_simple(claims, secret)` | Encode with HS256 and auto-set `iat` |
| `inspect(token)` | Decode the header without verifying the signature |
| `decode_without_validation(token)` | Decode claims without any verification (unsafe) |

| Type | Description |
|---|---|
| `Algorithm` | HMAC algorithm: `HS256`, `HS384`, `HS512` |
| `Header` | JWT header with algorithm and optional key ID |
| `Claims<T>` | Registered claims combined with custom typed claims |
| `RegisteredClaims` | Standard JWT claims (iss, sub, aud, exp, nbf, iat, jti) |
| `Validation` | Builder for configuring claim validation rules |
| `JwtError` | Error type for all JWT operations |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/rs-jwt)

🐛 [Report issues](https://github.com/philiprehberger/rs-jwt/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/rs-jwt/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
