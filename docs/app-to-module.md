# Cross-Reference: Application → DIS Module

> Which DIS module does each application consume, and for what? This file is
> the map from a Singra product to the underlying primitive it relies on.
> Use it when debugging or when planning to swap an implementation.

## Singra Vault (`github.com/mauntingstudios/singravault`)

The Vault is the most DIS-heavy application. It is **the reference
consumer**: nearly every DIS module is in use somewhere.

| Capability | Vault surface | DIS module |
| --- | --- | --- |
| Master-password KDF (Argon2id) | `deriveRawKey` / `deriveKey` | `kdf` |
| Device-key strengthening (HKDF) | `deriveRawKey(..., deviceKey)` | `kdf` |
| Vault item envelope (`sv-vault-v1:`) | `encryptVaultItem` / `decryptVaultItem` | `vault-encryption` |
| Two-tier key model (`usk-wrap-v2:`) | `createEncryptedUserKey` / `unwrapUserKey` / `rewrapUserKey` | `key-management` |
| Private-key wrapping (`usk-v1:`) | `wrapPrivateKeyWithUserKey` / `unwrapPrivateKeyWithUserKey` | `vault-crypto` |
| RSA-OAEP for emergency access | `generateRSAKeyPair` / `encryptRSA` / `decryptRSA` | `vault-crypto` (over `asymmetric`) |
| Hybrid PQ+RSA for sharing / emergency | `generateUserKeyPair(v2)` / `migrateToHybridKeyPair` | `vault-crypto` (over `post-quantum`) |
| OpLog ECDSA device signatures | `signEcdsaP256` / `verifyEcdsaP256` | `signing` |
| OpLog record/snapshot crypto | HKDF + AES-GCM | `kdf` / `aead` / `random` |
| OpLog integrity hashes | `sha256Bytes` / `sha256Hex` / `hmacSha256` | `integrity` |
| 2FA TOTP (Singra enrolment) | `verifyTotpCode` / `buildTotpUri` | `totp` |
| Password-manager authenticator codes | `generateTotpCode` / `buildTotpUriWithOptions` | `totp` (subpath) |
| HIBP password-strength (SHA-1) | `sha1Hex` | `integrity` |
| PKCE for OAuth (Web) | `sha256Bytes` / `randomBytes` | `integrity` / `random` |
| Password generator randomness | `randomInt` | `random` |
| Passkey PRF wrapping | `deriveHkdfAesGcmKey` | `kdf` |
| OPAQUE session binding | `hmacSha256` | `integrity` |
| Canonical-JSON hashing for integrity v2 | `sha256StringBase64` | `integrity` |
| Key material in memory | `SecureBuffer` | `secure-memory` |
| UUIDs in UI / orchestrators | `randomUuid` | `random` |
| Application-specific composition | `services/cryptoService.ts` is now a thin re-export of `@dis/shield/vault-crypto` | `vault-crypto` (Singra profile) |

## Singra Premium (`github.com/mauntingstudios/singra-premium`)

Premium is a sibling repository that historically aliased Singra Vault's
`src/services/*` for its own crypto. As of the Phase 4 cutover it imports
DIS directly.

| Capability | Premium surface | DIS module |
| --- | --- | --- |
| Vault item encryption (delegated to UserKey) | re-uses Vault's `@dis/shield/vault-crypto` | `vault-crypto` |
| Chunked file attachments | `encryptAttachment` / `decryptAttachment` | `file-encryption` |
| File-key wrap under UserKey | via `wrapFileKey` callback that calls into `vault-crypto.encrypt` | `file-encryption` + `vault-crypto` |
| PQ hybrid keypair for shared collections | re-uses Vault's surface | `vault-crypto` (over `post-quantum`) |

Premium is the second consumer and exists to test the "two tightly-coupled
apps adopt DIS" path that the architecture decision in `architecture.md`
calls out. See `docs/migration-plan.md` Phase 4 for the cutover steps.

## A future, third application

If you are starting a new application that consumes DIS, you probably do
**not** need `@dis/shield/vault-crypto`. That module is the Singra-Vault
profile; it bakes in the `SINGRA_*` HKDF info labels, the `sv-vault-v1:`
envelope, the `usk-wrap-v2:` user-key envelope, the `pq-v2:` shared-key
envelope, and the Singra `VaultItemData` shape.

For a new app:

1. Read [`docs/integration-guide.md`](integration-guide.md) first.
2. Compose from the low-level modules: `kdf`, `aead`, `vault-encryption`,
   `key-management`, `file-encryption`, `post-quantum`, `signing`, `totp`,
   `integrity`, `random`, `secure-memory`, `core`.
3. Define your **own** envelope prefixes (e.g. `myapp-record-v1:`) and
   **own** HKDF info labels. The contract is "pick a prefix, freeze it,
   add a new version rather than editing it". See
   [`docs/crypto-dependency-map.md`](crypto-dependency-map.md) for what
   the format constants are for the Singra profile; your profile will
   look the same, but the values are yours.

## What "Powered by DIS" means in code

If you display a "Powered by DIS — Defensive Integration Shield" badge,
the import is:

```ts
import { DIS_BRANDING } from '@dis/shield';
// DIS_BRANDING === 'Powered by DIS — Defensive Integration Shield'
```

Trademark and badge rules are in [`docs/licensing.md`](licensing.md).
Short version: non-commercial use of the badge is fine; commercial
re-branding requires a dual-license — see licensing.md.
