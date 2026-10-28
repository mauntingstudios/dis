# Security Policy

DIS is a cryptographic library. Please treat vulnerabilities responsibly.

## Reporting

Do **not** open public issues for security vulnerabilities. Report privately via
GitHub Security Advisories on this repository (or contact the maintainer
directly). Include affected versions, reproduction, and impact. We aim to
acknowledge within a few days.

## Security model

- DIS composes only audited primitives (Argon2id via `hash-wasm`, AES-256-GCM /
  HKDF / SHA-256 via WebCrypto, ML-KEM-768 via `@noble/post-quantum`). It does
  not invent cryptography.
- Security properties, accepted residual risks, and unverified assumptions are
  documented in [`docs/threat-model.md`](docs/threat-model.md) and
  [`docs/crypto-review.md`](docs/crypto-review.md).
- Persisted formats are versioned and fail closed on unknown versions. Vault
  items are written as `sv-vault-v2:` with the version in the AAD; v1 and
  AAD-bound legacy payloads are still read for compatibility. Legacy no-AAD
  payloads are readable only on an explicit migration path.
- File manifests are authenticated in version 2 (HMAC over metadata and the
  chunk list); version 1 manifests are read for compatibility and are not
  truncation-protected.

## Supported versions

Pre-1.0: only the latest `0.x` minor receives fixes.
