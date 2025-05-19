# Changelog

## 0.1.3 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility

## 0.1.2 (2026-03-27)

- Add GitHub issue templates, PR template, and dependabot configuration
- Update README badges and add Support section

## 0.1.1 (2026-03-22)

- Fix README and CI compliance

## 0.1.0 (2026-03-19)

- HMAC signing algorithms: HS256, HS384, HS512
- Typed claims with registered and custom fields
- Token encoding and decoding with signature verification
- Claim validation: expiration, not-before, issuer, audience
- Clock skew tolerance via configurable leeway
- Header inspection without signature verification
- Convenience `encode_simple` function for quick token creation
