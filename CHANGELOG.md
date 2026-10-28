# Changelog

All notable changes to the `@msdis/shield` library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] - 2026-10-29

### Security
- **File manifests v2**: `encryptAttachment` writes `FileManifestV2` with an
  HMAC-SHA-256 over all metadata and the chunk list (excluding
  `wrapped_file_key`, so a password re-wrap does not invalidate the MAC).
  Decryption verifies the MAC before any chunk I/O, plus chunk count, index
  continuity, the recomputed manifest root, size sums and the written byte
  count. v1 manifests remain readable but are not truncation-protected.
  `upgradeAttachmentManifest` lifts v1 to v2 after a successful decrypt by
  re-wrapping the file key under `sv-file-key-v2:`; the chunks stay unchanged.
- **Vault items v2**: `sv-vault-v2:` binds the version in the AAD
  (`sv-vault-v2:<entryId>`); stripping the prefix fails. v1 and AAD-bound
  legacy payloads remain readable by decision (documented downgrade limit).
- `randomInt` now rejects ranges above 2^32 instead of returning negative
  values for large ranges.
- Post-quantum key generation and hybrid encryption use the configured
  `CryptoProvider`, and sensitive buffers are wiped on error paths.
- ECDSA signing normalises `s` to the lower half of the curve order.
  Verification still accepts high-S signatures so stored signatures keep
  working.

### Added
- `sealVaultEntryString` / `openVaultEntryString` for callers that own their
  payload serialization (e.g. MSM vault padding).
- `upgradeAttachmentManifest`, `manifestMacContext`, `fileKeyAadV2`,
  `parseVaultEntryEnvelope`, `getVaultEntryEnvelopeVersion`.
- Negative tests for manifest truncation and metadata tampering, vault prefix
  downgrade, `randomInt` boundaries, PQ provider use, ECDSA malleability and
  the migration registry.
- `.github/dependabot.yml` for npm and GitHub Actions.

### Compatibility
- v1 vault items and v1 file manifests are still read; new writes use v2.
- `decryptAttachment` now returns `{ manifestVersion: 1 | 2 }`; callers that
  ignored the previous `void` result need no change.
- `encryptAttachment` returns `FileManifestV2`, which is assignable to
  `FileManifestV1` (it only adds `manifest_mac` and narrows `version`).

---

## [0.3.0] - 2026-09-26

### Added
- **`@msdis/shield/altcha`**: Fully local, privacy-preserving Proof-of-Work (PoW) CAPTCHA alternative based on SHA-256 and HMAC-SHA-256.
  - `createAltchaChallenge({ hmacKey, maxNumber?, expiresAt? })`: Generates a tamper-evident PoW challenge with random salt and HMAC-SHA-256 signature.
  - `verifyAltchaSolution(hmacKey, payload, replayCache?)`: Constant-time verification of client PoW payloads, expiration timestamps, and signature integrity.
  - Zero external tracking, zero cookies, zero third-party dependencies, and 100% GDPR/DSGVO compliant.
  - Seamlessly integrates with the official `<altcha-widget>` Web Component.
- Comprehensive test suite for `@msdis/shield/altcha` (`src/altcha/altcha.test.ts`).
- Documentation in `README.md`, `AGENTS.md`, `GEMINI.md`, and integration guides.

### Compatibility
- **Purely additive:** No existing module, signature, or wire format has been altered. Existing consumers on `0.2.x` upgrade with zero breaking changes.

---

## [0.2.2] - 2026-09-17

### Added
- **`@msdis/shield/messaging`**: Signal Double Ratchet protocol for stateful, secure end-to-end communication.
  - ECDH P-256 DH ratchet.
  - HKDF-SHA-256 symmetric ratchet.
  - AES-256-GCM message sealing with header bound as AAD.
  - Forward secrecy and post-compromise security with skipped-key support.

---

## [0.2.1] - 2026-07-09

### Added
- Vault crypto and multi-device key agreement refinements.

---

## [0.1.0] - 2026-06-13

### Added
- Initial core release of `@msdis/shield` (AEAD, KDF, SecureMemory, Asymmetric, Post-Quantum, Format-Versioning, File-Encryption).
