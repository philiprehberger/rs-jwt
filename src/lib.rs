//! JSON Web Token encoding, decoding, and validation with HMAC algorithms.
//!
//! This crate provides functions to create, verify, and inspect JWTs using
//! HMAC-based signing algorithms (HS256, HS384, HS512). It supports typed
//! custom claims, registered claim validation (expiration, not-before, issuer,
//! audience), and configurable clock skew tolerance.
//!
//! # Quick Start
//!
//! ```rust
//! use philiprehberger_jwt::{encode, decode, Algorithm, Claims, RegisteredClaims, Validation};
//!
//! let claims = Claims {
//!     registered: RegisteredClaims::default(),
//!     custom: serde_json::json!({"user": "alice"}),
//! };
//!
//! let token = encode(&claims, b"secret", Algorithm::HS256).unwrap();
//! let decoded: Claims<serde_json::Value> = decode(&token, b"secret", &Validation::default()).unwrap();
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// HMAC signing algorithm used for JWT signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256.
    HS256,
    /// HMAC using SHA-384.
    HS384,
    /// HMAC using SHA-512.
    HS512,
}

/// JWT header containing algorithm and type information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// The signing algorithm used.
    pub alg: Algorithm,
    /// The token type, always `"JWT"`.
    pub typ: String,
    /// Optional key ID for identifying the signing key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Header {
    /// Creates a new header with the given algorithm and `typ` set to `"JWT"`.
    pub fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            typ: "JWT".to_string(),
            kid: None,
        }
    }
}

/// Standard registered JWT claims as defined in RFC 7519.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisteredClaims {
    /// Issuer of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject of the token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience the token is intended for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time (as UTC Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Not-before time (as UTC Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Issued-at time (as UTC Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Unique token identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// JWT claims combining registered claims with custom typed data.
///
/// The registered and custom fields are flattened into a single JSON object
/// when serialized, so custom claim field names must not collide with
/// registered claim names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims<T: Serialize> {
    /// Standard registered claims.
    #[serde(flatten)]
    pub registered: RegisteredClaims,
    /// Application-specific custom claims.
    #[serde(flatten)]
    pub custom: T,
}

/// Configuration for JWT claim validation.
///
/// Use the builder methods to configure which checks are performed during
/// token decoding.
pub struct Validation {
    leeway: u64,
    validate_exp: bool,
    validate_nbf: bool,
    required_claims: Vec<String>,
    issuer: Option<String>,
    audience: Option<String>,
}

impl Default for Validation {
    /// Creates a default validation configuration with expiration and
    /// not-before checks enabled and zero leeway.
    fn default() -> Self {
        Self {
            leeway: 0,
            validate_exp: true,
            validate_nbf: true,
            required_claims: Vec::new(),
            issuer: None,
            audience: None,
        }
    }
}

impl Validation {
    /// Sets the clock skew tolerance in seconds.
    pub fn leeway(mut self, secs: u64) -> Self {
        self.leeway = secs;
        self
    }

    /// Enables or disables expiration (`exp`) validation.
    pub fn require_exp(mut self, validate: bool) -> Self {
        self.validate_exp = validate;
        self
    }

    /// Enables or disables not-before (`nbf`) validation.
    pub fn require_nbf(mut self, validate: bool) -> Self {
        self.validate_nbf = validate;
        self
    }

    /// Sets the expected issuer. If set, tokens with a different `iss` are rejected.
    pub fn issuer(mut self, iss: &str) -> Self {
        self.issuer = Some(iss.to_string());
        self
    }

    /// Sets the expected audience. If set, tokens with a different `aud` are rejected.
    pub fn audience(mut self, aud: &str) -> Self {
        self.audience = Some(aud.to_string());
        self
    }

    /// Sets claim names that must be present in the token.
    pub fn required_claims(mut self, claims: Vec<String>) -> Self {
        self.required_claims = claims;
        self
    }
}

/// Errors that can occur during JWT operations.
#[derive(Debug)]
pub enum JwtError {
    /// The token format is invalid (wrong number of segments).
    InvalidToken,
    /// The signature does not match the token contents.
    InvalidSignature,
    /// Base64 decoding failed.
    InvalidBase64(String),
    /// JSON serialization or deserialization failed.
    InvalidJson(String),
    /// The token has expired.
    ExpiredToken,
    /// The token is not yet valid (before `nbf`).
    NotYetValid,
    /// The issuer does not match the expected value.
    InvalidIssuer,
    /// The audience does not match the expected value.
    InvalidAudience,
    /// A required claim is missing from the token.
    MissingClaim(String),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtError::InvalidToken => write!(f, "invalid token format"),
            JwtError::InvalidSignature => write!(f, "invalid signature"),
            JwtError::InvalidBase64(msg) => write!(f, "invalid base64: {msg}"),
            JwtError::InvalidJson(msg) => write!(f, "invalid JSON: {msg}"),
            JwtError::ExpiredToken => write!(f, "token has expired"),
            JwtError::NotYetValid => write!(f, "token is not yet valid"),
            JwtError::InvalidIssuer => write!(f, "invalid issuer"),
            JwtError::InvalidAudience => write!(f, "invalid audience"),
            JwtError::MissingClaim(name) => write!(f, "missing required claim: {name}"),
        }
    }
}

impl std::error::Error for JwtError {}

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Computes the HMAC signature for the given message using the specified algorithm and secret.
fn sign(message: &[u8], secret: &[u8], algorithm: Algorithm) -> Vec<u8> {
    match algorithm {
        Algorithm::HS256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS384 => {
            let mut mac =
                Hmac::<Sha384>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Verifies the HMAC signature using constant-time comparison.
fn verify_signature(
    message: &[u8],
    signature: &[u8],
    secret: &[u8],
    algorithm: Algorithm,
) -> Result<(), JwtError> {
    match algorithm {
        Algorithm::HS256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.verify_slice(signature)
                .map_err(|_| JwtError::InvalidSignature)
        }
        Algorithm::HS384 => {
            let mut mac =
                Hmac::<Sha384>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.verify_slice(signature)
                .map_err(|_| JwtError::InvalidSignature)
        }
        Algorithm::HS512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).expect("HMAC accepts any key length");
            mac.update(message);
            mac.verify_slice(signature)
                .map_err(|_| JwtError::InvalidSignature)
        }
    }
}

/// Encodes claims into a signed JWT string.
///
/// Creates a token with the format `header.payload.signature` using the
/// specified HMAC algorithm.
///
/// # Errors
///
/// Returns [`JwtError::InvalidJson`] if the claims cannot be serialized.
pub fn encode<T: Serialize>(
    claims: &Claims<T>,
    secret: &[u8],
    algorithm: Algorithm,
) -> Result<String, JwtError> {
    let header = Header::new(algorithm);
    let header_json =
        serde_json::to_string(&header).map_err(|e| JwtError::InvalidJson(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let claims_json =
        serde_json::to_string(claims).map_err(|e| JwtError::InvalidJson(e.to_string()))?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

    let message = format!("{header_b64}.{claims_b64}");
    let signature = sign(message.as_bytes(), secret, algorithm);
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{message}.{signature_b64}"))
}

/// Splits a token string into its three parts.
fn split_token(token: &str) -> Result<(&str, &str, &str), JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtError::InvalidToken);
    }
    Ok((parts[0], parts[1], parts[2]))
}

/// Decodes a base64url-encoded string into bytes.
fn decode_b64(input: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| JwtError::InvalidBase64(e.to_string()))
}

/// Decodes and validates a JWT, returning the typed claims.
///
/// Verifies the HMAC signature using the provided secret, then validates
/// claims according to the [`Validation`] configuration.
///
/// # Errors
///
/// Returns an error if the token format is invalid, the signature does not
/// match, or any validation check fails.
pub fn decode<T: Serialize + DeserializeOwned>(
    token: &str,
    secret: &[u8],
    validation: &Validation,
) -> Result<Claims<T>, JwtError> {
    let (header_b64, claims_b64, signature_b64) = split_token(token)?;

    // Decode and parse header to get algorithm
    let header_bytes = decode_b64(header_b64)?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| JwtError::InvalidJson(e.to_string()))?;

    // Verify signature
    let message = format!("{header_b64}.{claims_b64}");
    let signature = decode_b64(signature_b64)?;
    verify_signature(message.as_bytes(), &signature, secret, header.alg)?;

    // Decode claims
    let claims_bytes = decode_b64(claims_b64)?;
    let claims: Claims<T> =
        serde_json::from_slice(&claims_bytes).map_err(|e| JwtError::InvalidJson(e.to_string()))?;

    // Validate claims
    let now = current_timestamp();

    if validation.validate_exp {
        if let Some(exp) = claims.registered.exp {
            if exp + validation.leeway < now {
                return Err(JwtError::ExpiredToken);
            }
        }
    }

    if validation.validate_nbf {
        if let Some(nbf) = claims.registered.nbf {
            if nbf > now + validation.leeway {
                return Err(JwtError::NotYetValid);
            }
        }
    }

    if let Some(ref expected_iss) = validation.issuer {
        match &claims.registered.iss {
            Some(iss) if iss == expected_iss => {}
            _ => return Err(JwtError::InvalidIssuer),
        }
    }

    if let Some(ref expected_aud) = validation.audience {
        match &claims.registered.aud {
            Some(aud) if aud == expected_aud => {}
            _ => return Err(JwtError::InvalidAudience),
        }
    }

    // Check required claims
    if !validation.required_claims.is_empty() {
        let claims_value = serde_json::to_value(&claims)
            .map_err(|e| JwtError::InvalidJson(e.to_string()))?;
        if let serde_json::Value::Object(map) = &claims_value {
            for claim in &validation.required_claims {
                if !map.contains_key(claim) {
                    return Err(JwtError::MissingClaim(claim.clone()));
                }
            }
        }
    }

    Ok(claims)
}

/// Decodes the JWT header without verifying the signature.
///
/// Useful for inspecting the algorithm or key ID before selecting a
/// verification key. Does not validate any claims.
///
/// # Errors
///
/// Returns an error if the token format is invalid or the header cannot
/// be parsed.
pub fn inspect(token: &str) -> Result<Header, JwtError> {
    let (header_b64, _, _) = split_token(token)?;
    let header_bytes = decode_b64(header_b64)?;
    serde_json::from_slice(&header_bytes).map_err(|e| JwtError::InvalidJson(e.to_string()))
}

/// Decodes claims from a JWT without verifying the signature.
///
/// **Warning:** This function does not verify the token signature or validate
/// any claims. Only use it for debugging or in trusted environments.
///
/// # Errors
///
/// Returns an error if the token format is invalid or the claims cannot
/// be deserialized.
pub fn decode_without_validation<T: Serialize + DeserializeOwned>(
    token: &str,
) -> Result<Claims<T>, JwtError> {
    let (_, claims_b64, _) = split_token(token)?;
    let claims_bytes = decode_b64(claims_b64)?;
    serde_json::from_slice(&claims_bytes).map_err(|e| JwtError::InvalidJson(e.to_string()))
}

/// Encodes claims using HS256 with `iat` automatically set to the current time.
///
/// This is a convenience wrapper around [`encode`] for simple use cases where
/// only custom claims are needed and HS256 is acceptable.
///
/// # Errors
///
/// Returns [`JwtError::InvalidJson`] if the claims cannot be serialized.
pub fn encode_simple<T: Serialize>(claims: &T, secret: &[u8]) -> Result<String, JwtError> {
    let wrapped = Claims {
        registered: RegisteredClaims {
            iat: Some(current_timestamp()),
            ..Default::default()
        },
        custom: serde_json::to_value(claims).map_err(|e| JwtError::InvalidJson(e.to_string()))?,
    };
    encode(&wrapped, secret, Algorithm::HS256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    fn future_timestamp(secs: u64) -> u64 {
        current_timestamp() + secs
    }

    fn past_timestamp(secs: u64) -> u64 {
        current_timestamp().saturating_sub(secs)
    }

    fn make_claims() -> Claims<serde_json::Value> {
        Claims {
            registered: RegisteredClaims {
                sub: Some("user-123".into()),
                exp: Some(future_timestamp(3600)),
                iat: Some(current_timestamp()),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        }
    }

    #[test]
    fn test_encode_decode_roundtrip_hs256() {
        let claims = make_claims();
        let secret = b"test-secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let decoded: Claims<serde_json::Value> =
            decode(&token, secret, &Validation::default()).unwrap();
        assert_eq!(decoded.registered.sub, Some("user-123".into()));
    }

    #[test]
    fn test_encode_decode_hs384() {
        let claims = make_claims();
        let secret = b"test-secret-384";
        let token = encode(&claims, secret, Algorithm::HS384).unwrap();
        let decoded: Claims<serde_json::Value> =
            decode(&token, secret, &Validation::default()).unwrap();
        assert_eq!(decoded.registered.sub, Some("user-123".into()));
    }

    #[test]
    fn test_encode_decode_hs512() {
        let claims = make_claims();
        let secret = b"test-secret-512";
        let token = encode(&claims, secret, Algorithm::HS512).unwrap();
        let decoded: Claims<serde_json::Value> =
            decode(&token, secret, &Validation::default()).unwrap();
        assert_eq!(decoded.registered.sub, Some("user-123".into()));
    }

    #[test]
    fn test_invalid_signature() {
        let claims = make_claims();
        let token = encode(&claims, b"secret-1", Algorithm::HS256).unwrap();
        let result: Result<Claims<serde_json::Value>, _> =
            decode(&token, b"secret-2", &Validation::default());
        assert!(matches!(result, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn test_expired_token() {
        let claims = Claims {
            registered: RegisteredClaims {
                exp: Some(past_timestamp(100)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let result: Result<Claims<serde_json::Value>, _> =
            decode(&token, secret, &Validation::default());
        assert!(matches!(result, Err(JwtError::ExpiredToken)));
    }

    #[test]
    fn test_not_yet_valid() {
        let claims = Claims {
            registered: RegisteredClaims {
                nbf: Some(future_timestamp(3600)),
                exp: Some(future_timestamp(7200)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let result: Result<Claims<serde_json::Value>, _> =
            decode(&token, secret, &Validation::default());
        assert!(matches!(result, Err(JwtError::NotYetValid)));
    }

    #[test]
    fn test_leeway_allows_slightly_expired() {
        let claims = Claims {
            registered: RegisteredClaims {
                exp: Some(past_timestamp(5)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let validation = Validation::default().leeway(30);
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(result.is_ok());
    }

    #[test]
    fn test_issuer_validation() {
        let claims = Claims {
            registered: RegisteredClaims {
                iss: Some("my-app".into()),
                exp: Some(future_timestamp(3600)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();

        // Correct issuer
        let validation = Validation::default().issuer("my-app");
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(result.is_ok());

        // Wrong issuer
        let validation = Validation::default().issuer("other-app");
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(matches!(result, Err(JwtError::InvalidIssuer)));
    }

    #[test]
    fn test_audience_validation() {
        let claims = Claims {
            registered: RegisteredClaims {
                aud: Some("my-api".into()),
                exp: Some(future_timestamp(3600)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();

        // Correct audience
        let validation = Validation::default().audience("my-api");
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(result.is_ok());

        // Wrong audience
        let validation = Validation::default().audience("other-api");
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(matches!(result, Err(JwtError::InvalidAudience)));
    }

    #[test]
    fn test_inspect_returns_header() {
        let claims = make_claims();
        let token = encode(&claims, b"secret", Algorithm::HS384).unwrap();
        let header = inspect(&token).unwrap();
        assert_eq!(header.alg, Algorithm::HS384);
        assert_eq!(header.typ, "JWT");
    }

    #[test]
    fn test_decode_without_validation() {
        let claims = Claims {
            registered: RegisteredClaims {
                sub: Some("test-sub".into()),
                exp: Some(past_timestamp(9999)),
                ..Default::default()
            },
            custom: serde_json::json!({"foo": "bar"}),
        };
        let token = encode(&claims, b"secret", Algorithm::HS256).unwrap();

        // Decode with wrong secret and expired — should still work
        let decoded: Claims<serde_json::Value> = decode_without_validation(&token).unwrap();
        assert_eq!(decoded.registered.sub, Some("test-sub".into()));
    }

    #[test]
    fn test_custom_claims_struct() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct MyClaims {
            role: String,
            level: u32,
        }

        let claims = Claims {
            registered: RegisteredClaims {
                exp: Some(future_timestamp(3600)),
                ..Default::default()
            },
            custom: MyClaims {
                role: "admin".into(),
                level: 5,
            },
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let decoded: Claims<MyClaims> = decode(&token, secret, &Validation::default()).unwrap();
        assert_eq!(decoded.custom.role, "admin");
        assert_eq!(decoded.custom.level, 5);
    }

    #[test]
    fn test_empty_custom_claims() {
        let claims = Claims {
            registered: RegisteredClaims {
                sub: Some("user".into()),
                exp: Some(future_timestamp(3600)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();
        let decoded: Claims<serde_json::Value> =
            decode(&token, secret, &Validation::default()).unwrap();
        assert_eq!(decoded.registered.sub, Some("user".into()));
    }

    #[test]
    fn test_malformed_token_missing_parts() {
        let result: Result<Claims<serde_json::Value>, _> =
            decode("only.two", b"secret", &Validation::default());
        assert!(matches!(result, Err(JwtError::InvalidToken)));

        let result: Result<Claims<serde_json::Value>, _> =
            decode("nope", b"secret", &Validation::default());
        assert!(matches!(result, Err(JwtError::InvalidToken)));
    }

    #[test]
    fn test_malformed_token_bad_base64() {
        let result: Result<Claims<serde_json::Value>, _> =
            decode("!!!.@@@.###", b"secret", &Validation::default());
        assert!(matches!(
            result,
            Err(JwtError::InvalidBase64(_)) | Err(JwtError::InvalidJson(_))
        ));
    }

    #[test]
    fn test_encode_simple() {
        #[derive(Serialize, Deserialize, Debug)]
        struct Payload {
            user_id: u64,
        }

        let token = encode_simple(&Payload { user_id: 42 }, b"secret").unwrap();

        // Should be decodable
        let decoded: Claims<serde_json::Value> =
            decode(&token, b"secret", &Validation::default()).unwrap();
        assert!(decoded.registered.iat.is_some());
        assert_eq!(decoded.custom["user_id"], 42);
    }

    #[test]
    fn test_required_claims_validation() {
        let claims = Claims {
            registered: RegisteredClaims {
                exp: Some(future_timestamp(3600)),
                ..Default::default()
            },
            custom: serde_json::json!({}),
        };
        let secret = b"secret";
        let token = encode(&claims, secret, Algorithm::HS256).unwrap();

        let validation = Validation::default().required_claims(vec!["sub".into()]);
        let result: Result<Claims<serde_json::Value>, _> = decode(&token, secret, &validation);
        assert!(matches!(result, Err(JwtError::MissingClaim(_))));
    }
}
