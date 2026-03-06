# Security Policy — sentinel-ai

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Security Standards

This service adheres to the Trancendos 2060 Security Standard:

- **Authentication**: HS512 JWT via `@trancendos/iam-middleware`
- **Authorization**: RBAC + ABAC 5-step evaluation chain
- **Cryptography**: SHA-512 integrity hashes, bcrypt passwords
- **Transport**: TLS 1.3+ in production
- **OWASP**: Helmet.js, CORS, rate limiting
- **Zero-Trust**: Every request verified, least-privilege

## Reporting Vulnerabilities

Report security vulnerabilities to the Continuity Guardian.
Do NOT create public GitHub issues for security vulnerabilities.

## 2060 Quantum-Safe Migration Path

`hmac_sha512` → `ml_kem (2030)` → `hybrid_pqc (2040)` → `slh_dsa (2060)`
