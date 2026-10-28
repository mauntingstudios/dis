# Public API Design

Stability contract: the symbols below are the supported surface. They follow
semantic versioning. Internal changes (KDF tuning within a version, provider
internals) must not change these signatures.

## Stability tiers

- **Stable** — covered by semver; breaking changes require a major bump and a
  migration note.
- **Format-frozen** — string constants that appear in persisted data. These are
  never edited; new behaviour means a new versioned constant.

## High-level SDK (`@dis/shield`)

```ts
// Vault entries (content-key in, opaque record out)
encryptVaultEntry(data, key, entryId): Promise<string>   // -> "sv-vault-v2:..."
decryptVaultEntry(sealed, key, entryId): Promise<Record<string, unknown>>
decryptVaultEntryForMigration(sealed, key, entryId): Promise<VaultEntryMigrationResult>
sealVaultEntryString(plaintext, key, entryId): Promise<string>
openVaultEntryString(sealed, key, entryId): Promise<{ plaintext, version }>
isCurrentVaultEntryEnvelope(sealed): boolean

// Attachments (storage-agnostic; caller supplies chunk IO + key wrap)
encryptAttachment(input: EncryptAttachmentInput): Promise<{ manifest: FileManifestV2; manifestRoot: string }>
decryptAttachment(input: DecryptAttachmentInput): Promise<{ manifestVersion: 1 | 2 }>
upgradeAttachmentManifest(input: UpgradeAttachmentManifestInput): Promise<FileManifestV2>

interface AttachmentContext {
  readonly ownerId: string;
  readonly vaultItemId: string;
  readonly fileId: string;
}

interface EncryptAttachmentInput {
  readonly context: AttachmentContext;
  readonly fileRevision?: number;
  readonly chunkSize?: number;
  readonly totalSize: number;
  readonly readChunk: (start: number, end: number) => Promise<Uint8Array>;
  readonly writeChunk: (index: number, ciphertextBase64: string) => Promise<number>;
  readonly wrapFileKey: (fileKeyBytes: Uint8Array, aad: string) => Promise<string>;
  readonly metadata: {
    readonly original_name: string;
    readonly mime_type: string | null;
    readonly last_modified: number | null;
  };
}

interface DecryptAttachmentInput {
  readonly context: AttachmentContext;
  readonly manifest: FileManifest;
  readonly readChunk: (index: number, storedSha256: string) => Promise<string>;
  readonly writeChunk: (index: number, plaintext: Uint8Array) => Promise<void>;
  readonly unwrapFileKey: (wrappedKey: string, aad: string) => Promise<Uint8Array>;
  readonly verifyChunkHashes?: boolean;
}

// Secure Memory Buffer
class SecureBuffer {
  readonly size: number;
  readonly isDestroyed: boolean;
  constructor(size: number);
  static fromBytes(bytes: Uint8Array): SecureBuffer;
  static fromHex(hex: string): SecureBuffer;
  static random(size: number): SecureBuffer;
  use<T>(fn: (data: Uint8Array) => T): T;
  useAsync<T>(fn: (data: Uint8Array) => Promise<T>): Promise<T>;
  destroy(): void;
  toBytes(): Uint8Array;
  equals(other: SecureBuffer | Uint8Array): boolean;
}

// KDF (see @dis/shield/kdf for low-level access; vault-crypto profile below)
deriveMasterKey(password, saltBase64, opts?): Promise<CryptoKey>  // == deriveAesGcmKey
deriveRawKey(password, saltBase64, opts?): Promise<Uint8Array>
generateSalt(): string

// Note: `KDF_PARAMS` is **not** exported from the SDK facade.
// The SDK re-exports `CURRENT_KDF_VERSION` and `DEFAULT_KDF_PARAMS` from
// @dis/shield/kdf. The plain-record `KDF_PARAMS` alias lives in
// @dis/shield/vault-crypto and is meant for Singra's call sites that look
// up params by version. For new applications, prefer `DEFAULT_KDF_PARAMS`
// from the SDK facade or @dis/shield/kdf.

// Two KDF paths exist — pick by what you need:
//
// (1) Generic: takes a typed `opts.strengthen` for HKDF-Expand second-factor binding
deriveAesGcmKey(password, saltBase64, {
  version?: number,                  // KDF version registry; defaults to CURRENT_KDF_VERSION
  params?: Readonly<Record<number, KdfParams>>,  // optional override
  strengthen?: {                     // optional HKDF second-factor binding
    hkdfSalt: Uint8Array,
    info: string,                    // caller-owned domain-separation label
  },
}): Promise<CryptoKey>

// (2) Singra Vault profile (vault-crypto): positional `deviceKey` is the common case
deriveRawKey(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<Uint8Array>
deriveKey(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<CryptoKey>
deriveRawKeySecure(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<SecureBuffer>
//
// When `deviceKey` is supplied, DIS strengthens the Argon2id output via HKDF-Expand
// with HKDF info = 'SINGRA_DEVICE_KEY_V1' and salt = the device key bytes.
// (The `info` string is part of the wire-format contract; see crypto-dependency-map.md.)

// Key management
createWrappedUserKey(kdfOutputBytes, scheme?): Promise<UserKeyBundle>
unwrapUserKey(encryptedUserKey, kdfOutputBytes, scheme?): Promise<CryptoKey>
rotateEncryptionKeys(encryptedUserKey, oldKdf, newKdf, scheme?): Promise<string>

// TOTP — the SDK facade re-exports the 2FA-enrolment surface only.
// For password-manager authenticator code (third-party imported entries
// with non-default algorithm / digits / period), import directly:
//   import { generateTotpCode, buildTotpUriWithOptions } from '@dis/shield/totp'
// The SDK export intentionally omits these so the 2FA-enrolment contract
// (SHA-1 / 6 digits / 30 s) is the only thing 2FA call sites can reach.
generateTotpSecret(): string
buildTotpUri({ issuer, label, secret }): string
verifyTotpCode(secret, code, window?): boolean

// Integrity & migrations
verifyPayloadIntegrity(bytes, expectedBase64): Promise<void>

// Migration framework — see docs/migrations.md for the full guide.
// DIS provides the framework; the application registers concrete steps.
new MigrationRegistry().register(migration: Migration).migrateToLatest(
  subject: string,
  payload: string,
  detect: VersionDetector,
  context: MigrationContext,
): Promise<string>

// ---- Two functions share a name across modules — read carefully. -----------
//
// (a) Storage-format migration for a wrapped private key.
//     Lives in @dis/shield/vault-crypto. Rewrites a stored
//     'salt:enc' / 'ver:salt:enc' private-key blob to the hybrid
//     'pq-v2:ver:salt:encRsa:encPq' form.
migrateToHybridKeyPair(encryptedPrivateKey: string, masterPassword: string):
  Promise<{ publicKey: string; encryptedPrivateKey: string; pqPublicKey: string } | null>

// (b) Cipher-version migration for an already-hybrid PQ+RSA ciphertext.
//     Lives in @dis/shield/post-quantum. Re-encodes a v1 (0x01 RSA-only),
//     legacy (0x02), or standard v1 (0x03) hybrid ciphertext into the
//     current standard v2 (0x04). Byte-layout preserved.
migrateToHybrid(
  legacyCiphertext: string,
  rsaPrivateKey: string,            // JWK string
  pqSecretKey: string | null,       // base64; required for 0x02 and 0x03
  pqPublicKey: string,              // base64
  rsaPublicKey: string,             // JWK string
  aad?: string,
): Promise<string>
//
// Use (a) when you are reading a legacy stored private key and want to
// upgrade its storage format. Use (b) when you already have a hybrid
// ciphertext at an old version and want to refresh it in place.
```

### Messaging — Double Ratchet (`@dis/shield/messaging`)

```ts
// Key pairs and session setup. `sharedSecret` (32 bytes) comes from a
// handshake — X3DH or otherwise — that DIS deliberately does not implement.
generateRatchetKeyPair(): Promise<RatchetDhKeyPair>            // ECDH P-256
initSenderState(input: InitSenderStateInput): Promise<RatchetState>
initReceiverState(input: InitReceiverStateInput): Promise<RatchetState>

// Pure state transitions — neither call mutates or wipes its input state.
encryptMessage(state, plaintext: Uint8Array):
  Promise<{ nextState: RatchetState; message: RatchetMessage }>
decryptMessage(state, message: RatchetMessage):
  Promise<{ nextState: RatchetState; plaintext: Uint8Array }>

// Persistence and lifetime.
serializeRatchetState(state): string          // -> "sv-dr-state-v1:{…}"
deserializeRatchetState(json: string): RatchetState
serializeRatchetMessage(message): string      // -> "sv-dr-msg-v1:{…}"
deserializeRatchetMessage(wire: string): RatchetMessage
destroyRatchetState(state): void              // zeroes every secret it holds

DEFAULT_MAX_SKIPPED_KEYS: 1000
```

**Format-frozen:** `sv-dr-msg-v1:`, `sv-dr-state-v1:`, and the HKDF `info`
labels `sv-dr-root-v1`, `sv-dr-chain-v1`, `sv-dr-msg-v1`. The state records
its DH algorithm (`ECDH-P-256`) so a future `sv-dr-state-v2` can introduce
another curve without ambiguity.

**Contracts specific to this module:**

- The caller owns state lifetime. Persist `nextState`, then call
  `destroyRatchetState` on the state it replaced — keeping the old one alive
  keeps its chain keys alive, defeating the forward secrecy the ratchet
  exists to provide.
- `decryptMessage` works on a private clone and commits only after the GCM
  tag verifies. A forged or replayed message leaves the input state
  byte-for-byte unchanged, so it can neither advance nor wedge a session.
- A consumed skipped message key is removed from the returned state
  irrevocably; replaying that message afterwards raises `DisDecryptionError`.
- `maxSkippedKeys` bounds both retained keys (oldest evicted, FIFO) and the
  number of ratchet steps one message may force — the second half is what
  stops a header claiming `n = 2^31` from burning CPU.
- The receiving party has no sending chain until it has decrypted its first
  inbound message; calling `encryptMessage` before that is
  `DisInvalidArgumentError`.

## Design rules

1. **Keys, not passwords, cross most APIs.** Only `kdf` accepts a password.
   Everything else takes a `CryptoKey` or raw bytes, enforcing key separation.
2. **AAD is mandatory and explicit** where context binding matters
   (`entryId`, attachment context). It is a required parameter, not optional.
3. **Caller owns secret lifetime.** Functions returning `Uint8Array` secrets
   document that the caller must wipe; DIS wipes everything it allocates
   internally.
4. **No app types leak in.** A vault entry is `Record<string, unknown>`; an
   attachment's storage is expressed as `readChunk`/`writeChunk` callbacks.
5. **Errors are typed and secret-free.** All decrypt failures collapse to
   `DisDecryptionError` (no oracle). Unknown versions →
   `DisUnsupportedFormatVersionError`. Legacy on runtime path →
   `DisLegacyPayloadError`.
6. **Providers are injectable** via `setCryptoProvider` for tests/hardware.

## Error handling

DIS throws typed errors from `@dis/shield/core`. Map them to user-facing
copy in your application; do not surface raw `message` to end users (some
include stack-trace-ish details that are not useful to a user and may
leak internal state). Do not switch on the string of the message — switch
on the `code` property or the constructor.

| Error class | `code` (when applicable) | When it fires | Suggested app behaviour |
| --- | --- | --- | --- |
| `DisDecryptionError` | — | AEAD failure: wrong key, tampered ciphertext, or wrong AAD | Treat as "wrong password" or "data corruption". Do **not** expose the cause — there is no oracle, by design. |
| `DisIntegrityError` | — | SHA-256 verification of a stored payload (manifest, hash chain) failed | Trigger quarantine / re-fetch from a trusted source / log for the security team. |
| `DisUnsupportedFormatVersionError` | — | Ciphertext carries an unknown in-family version prefix (e.g. `sv-vault-v9:`) | Refuse to read. Ask the user to update the app. |
| `DisLegacyPayloadError` | — | Runtime read hit an unversioned / no-AAD payload | Refuse on the runtime path. Re-try through the explicit migration helper (`decryptVaultEntryForMigration` etc.) or refuse. |
| `DisInvalidArgumentError` | — | Caller passed a bad argument (empty string, wrong length, missing required AAD, …) | Programming error in the app. Log and surface a generic error. |
| `DisError` | `'UNSUPPORTED_KDF_VERSION'` | The KDF version stored for an account is not in the registry | Refuse unlock. Ask the user to update (or roll back, but never silently upgrade). |
| `DisError` | `'KEY_DERIVATION_FAILED'` | Argon2id output was the wrong type | Should not happen; report as a bug. |
| `DisError` | `'INVALID_ARGUMENT'` | Migration cycle detected | The migration registry has a bug; report. |
| `DisError` | `'SECURITY_STANDARD_BLOCKED'` (post-quantum) | Hybrid ciphertext at a version not permitted by the security standard | Refuse. Run the migration helper (`migrateToHybrid`) explicitly. |

**The contract:** AEAD failures do not reveal cause (no padding/AAD oracle).
Your error UX must respect that. Log the type for yourself, but show the
user a generic "could not decrypt — wrong password or corrupted data"
message.

## Breaking-change policy

- Format-frozen constants are append-only (`sv-vault-v1` → add `sv-vault-v2`,  never edit v1). Decryption keeps reading all supported versions.
- Removing a legacy read path is a **major** change and requires documented
  evidence that no data depends on it.
- New optional parameters are minor; new required parameters are major.

## Breaking-change risks for the apps (at cutover)

| Change | Risk | Handling |
| --- | --- | --- |
| Premium `../singravault/src` alias → `@dis/shield` | import paths change | codemod + adapter, single PR |
| App crypto modules deleted | dangling imports | app-local `crypto` adapter re-exports DIS |
| Raw `crypto.subtle` banned | lint failures | provide adapter; fix call sites |
| Legacy no-AAD runtime read removed | old data unreadable | only after migration + telemetry gate |
