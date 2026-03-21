# Changelog

## 0.1.0 (2026-03-19)

- HMAC signing algorithms: HS256, HS384, HS512
- Typed claims with registered and custom fields
- Token encoding and decoding with signature verification
- Claim validation: expiration, not-before, issuer, audience
- Clock skew tolerance via configurable leeway
- Header inspection without signature verification
- Convenience `encode_simple` function for quick token creation
