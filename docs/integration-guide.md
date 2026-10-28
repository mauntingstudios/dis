# Integration Guide

> **Who is this for?** A new application that wants to consume `@msdis/shield`
> for its cryptography. After reading this, you should be able to wire a
> master-password unlock, a vault-item store/load cycle, a wrapped private
> key for sharing, and a chunked file attachment, without reading the
> DIS source code.

This guide follows the shape of the Singra Vault + Singra Premium cutover,
but the steps are generic.

## 0. Decide what you actually need

Most apps only need a subset of DIS. Pick the smallest surface that solves
your problem.

| If you need… | You want… |
| --- | --- |
| Derive a key from a master password | `deriveMasterKey` (the `kdf` module, surfaced as `deriveAesGcmKey`) |
| Encrypt/decrypt structured data with a key | `encryptVaultEntry` / `decryptVaultEntry` (the `vault-encryption` module) |
| Two-tier key model so password change does not re-encrypt data | `createWrappedUserKey` / `unwrapUserKey` / `rotateWrappedKey` (the `key-management` module) |
| Chunked file attachments with a manifest | `encryptAttachment` / `decryptAttachment` (the `file-encryption` module) |
| Sharing / emergency access with post-quantum forward secrecy | `generateHybridKeyPair` / `hybridWrapKey` / `hybridUnwrapKey` (the `post-quantum` module) |
| ECDSA signatures for an audit log | `generateEcdsaP256KeyPair` / `signEcdsaP256` / `verifyEcdsaP256` (the `signing` module) |
| TOTP for in-app authenticator or for 2FA | `generateTotpSecret` / `verifyTotpCode` / `generateTotpCode` (the `totp` module) |
| Forward secrecy for a message stream (per-message keys, self-healing) | `initSenderState` / `encryptMessage` / `decryptMessage` (the `messaging` module) |

For Singra Vault's exact composition of all of the above, see
`docs/architecture.md` (Module boundaries) and `@msdis/shield/vault-crypto`
(the application-specific composition Singra uses).

## 1. Install

```bash
npm install @msdis/shield
```

`@msdis/shield` pins Node `>=20.19.0` (the same constraint Singra Vault uses).
No other runtime dependencies are required unless you use the
`post-quantum` module, in which case install the optional peer:

```bash
npm install @noble/post-quantum
```

## 2. The core flow: master password → key → vault item

The pattern is always the same:

```
master password + salt  ──Argon2id──▶  KEK (raw bytes or CryptoKey)
                                          │
                                          │  (optional: HKDF-strengthen with device key)
                                          │
                                          ▼
                                    content key (UserKey)  ◀── rotated on password change,
                                          │                    no data re-encryption
                                          │
                                          ▼
                                    vault items  (sv-vault-v2: envelope, AAD = sv-vault-v2:entry id)
```

```ts
import { deriveRawKey, generateSalt, createWrappedUserKey, unwrapUserKey,
         encryptVaultEntry, decryptVaultEntry } from '@msdis/shield';

// 1) Account setup: generate salt and a wrapped user key. Store both.
const salt = generateSalt();
const kdfBytes = await deriveRawKey(masterPassword, salt);
const { encryptedUserKey, userKey } = await createWrappedUserKey(kdfBytes);
// → persist (salt, encryptedUserKey). Keep kdfBytes in a SecureBuffer; wipe when done.

// 2) Unlock: re-derive and unwrap the user key.
const kdfBytes = await deriveRawKey(masterPassword, storedSalt);
const userKey = await unwrapUserKey(storedEncryptedUserKey, kdfBytes);

// 3) Encrypt a vault item. The entryId binds the ciphertext to its row.
const sealed = await encryptVaultEntry(
  { title: 'GitHub', username: 'me', password: '...' },
  userKey,
  entryId,
);

// 4) Decrypt it later. The AAD matches the entryId, so swap-attacks fail closed.
const plain = await decryptVaultEntry(sealed, userKey, entryId);
```

**Wire-format note.** The `encryptedUserKey` string is `usk-wrap-v2:<base64>`.
The `sealed` item is `sv-vault-v2:<base64>` (v1 is still read). Both prefixes are part of the
format contract — see `docs/crypto-dependency-map.md` for the full list of
frozen constants. **Never change a published prefix.** Add a new version
instead.

## 3. Password change without re-encrypting data

```ts
import { deriveRawKey, rotateWrappedKey } from '@msdis/shield';

const oldKdfBytes = await deriveRawKey(oldPassword, salt, OLD_KDF_VERSION);
const newKdfBytes = await deriveRawKey(newPassword, salt, CURRENT_KDF_VERSION);

const newEncryptedUserKey = await rotateWrappedKey(
  oldEncryptedUserKey, oldKdfBytes, newKdfBytes,
);
// → overwrite encryptedUserKey in the database. Vault data is unchanged.
```

If you also use a device key for second-factor strengthening, pass it to
**both** `deriveRawKey` calls. The HKDF info label `SINGRA_DEVICE_KEY_V1`
is the same on both sides (it's the wire-format contract for the
strengthening step — see `crypto-dependency-map.md`).

## 4. Chunked file attachments

Use `encryptAttachment` / `decryptAttachment`. You supply the storage; DIS
supplies the cryptography and the manifest.

```ts
import { encryptAttachment, decryptAttachment } from '@msdis/shield/file-encryption';

const { manifest, manifestRoot } = await encryptAttachment({
  context: { ownerId, vaultItemId, fileId },
  totalSize: file.byteLength,
  readChunk: async (start, end) => new Uint8Array(await file.slice(start, end).arrayBuffer()),
  writeChunk: async (index, ciphertextBase64) => {
    await objectStore.put(`chunks/${fileId}/${index}`, ciphertextBase64);
    return ciphertextBase64.length; // stored size in bytes
  },
  wrapFileKey: (fileKeyBytes, aad) =>
    vaultEncrypt(fileKeyBytes, userKey, aad),  // your existing vault AEAD entry
  metadata: { original_name: file.name, mime_type: file.type, last_modified: file.lastModified },
});
// → persist manifest. chunkSize defaults to 4 MiB.
```

For decryption, you pass back the manifest, the matching context, and DIS streams chunks through your `readChunk` / `writeChunk` callbacks:

```ts
import { decryptAttachment } from '@msdis/shield/file-encryption';

const decryptedBytes = new Uint8Array(manifest.original_size);

await decryptAttachment({
  manifest,
  context: { ownerId, vaultItemId, fileId },
  readChunk: async (index, storedSha256) => {
    return await objectStore.get(`chunks/${fileId}/${index}`); // returns ciphertext base64
  },
  writeChunk: async (index, plaintextBytes) => {
    // Write the decrypted chunk bytes to the correct offset
    decryptedBytes.set(plaintextBytes, index * manifest.chunk_size);
  },
  unwrapFileKey: async (wrappedKey, aad) => {
    return await vaultDecrypt(wrappedKey, userKey, aad); // returns raw key bytes
  }
});
```

Each chunk is authenticated by its AAD (`sv-file-chunk-v1:owner:item:file:rev:manifestRoot:idx:count`). A storage operator cannot reorder, splice, or swap chunks undetected.

## 5. Sharing and emergency access (post-quantum hybrid)

> **Scope:** Use this for keys that need to survive "harvest now, decrypt
> later" adversaries. **Not** the encryption layer for vault item payloads.

```ts
import { generateHybridKeyPair, hybridWrapKey, hybridUnwrapKey } from '@msdis/shield/post-quantum';

// Per user (or per device that may act as grantor):
const { rsaPublicKey, rsaPrivateKey, pqPublicKey, pqSecretKey } = await generateHybridKeyPair();
// → store (rsaPrivateKey, pqSecretKey) wrapped under the user's UserKey. Publish
//   (rsaPublicKey, pqPublicKey) so other users can wrap shared keys to you.

// Per shared key, per recipient:
const wrapped = await hybridWrapKey(sharedKeyJwk, recipientPqPublicKey, recipientRsaPublicKey,
  `sv:shared-key:v1:${collectionId}:${senderUserId}:${recipientUserId}:${keyVersion}`);
// → persist the wrapped blob; only the recipient can unwrap it.

// On the recipient side:
const sharedKeyJwk = await hybridUnwrapKey(
  wrapped, recipientPqSecretKey, recipientRsaPrivateKey,
  `sv:shared-key:v1:${collectionId}:${senderUserId}:${recipientUserId}:${keyVersion}`,
);
```

**Important:** the AAD string on wrap **must equal** the AAD string on
unwrap, byte-for-byte. Use `buildSharedKeyWrapAad({ … })` to construct it
deterministically.

## 6. Audit-log signatures (ECDSA P-256)

```ts
import { generateEcdsaP256KeyPair, signEcdsaP256, verifyEcdsaP256,
         importEcdsaP256PublicKeySpki } from '@msdis/shield/signing';

const { privateKey, publicKey, publicKeySpki } = await generateEcdsaP256KeyPair();
// → privateKey is non-extractable. Store publicKeySpki (base64url) for verifiers.

const sig = await signEcdsaP256(privateKey, canonicalRecordBytes);
// → 64 bytes (r || s). Persist alongside the record.

const ok = await verifyEcdsaP256(
  await importEcdsaP256PublicKeySpki(storedSpki),
  sig, canonicalRecordBytes,
);
```

DIS does not define canonicalization. You decide the byte string that gets
signed. The wire format is fixed (raw `r || s`, 64 bytes); the meaning of
the bytes is yours.

## 7. TOTP for in-app authenticator or 2FA

```ts
import { generateTotpSecret, buildTotpUri, verifyTotpCode,
         generateTotpCode, buildTotpUriWithOptions } from '@msdis/shield/totp';

// Enroll: generate secret, show QR code from the otpauth:// URI.
const secret = generateTotpSecret();
const uri = buildTotpUri({ issuer: 'Singra', label: 'me@example.com', secret });
// → user scans; their authenticator now produces 6-digit codes every 30s.

// Verify at login.
const ok = await verifyTotpCode(secret, userInputCode);

// Password-manager authenticator view: code generation for a third-party
// imported entry (algorithm/digits/period may differ from the Singra default).
const code = generateTotpCode(importedSecret, { algorithm: 'SHA256', digits: 8, period: 60 });
const importedUri = buildTotpUriWithOptions(
  { issuer, label, secret: importedSecret },
  { algorithm: 'SHA256', digits: 8, period: 60 },
);
```

Singra's own 2FA enrolment uses `verifyTotpCode` with the pinned default
(`SHA1` / 6 digits / 30 s). Imported entries use `generateTotpCode` with
explicit per-entry options.

## 8. Message streams with forward secrecy (Double Ratchet)

Everything above protects data **at rest**: recover the key and you recover
every payload it ever sealed. The `messaging` module is for a running
conversation, where that is not good enough. Each message gets its own key
that is destroyed after use (forward secrecy), and every change of direction
mixes a fresh ECDH agreement into the session, so one uncompromised round
trip locks an attacker back out (post-compromise security).

**What DIS does not do here:** the initial handshake. X3DH, key servers and
identity verification are yours. DIS takes 32 agreed bytes and runs the
ratchet over them.

```ts
import {
  generateRatchetKeyPair, initSenderState, initReceiverState,
  encryptMessage, decryptMessage,
  serializeRatchetState, deserializeRatchetState, destroyRatchetState,
} from '@msdis/shield/messaging';

// Bob publishes a ratchet public key; both sides already agreed sharedSecret.
const bobPair = await generateRatchetKeyPair();

let alice = await initSenderState({
  sharedSecret,                        // 32 bytes, from your handshake
  remotePublicKey: bobPair.publicKey,
  associatedData: utf8ToBytes('alice:bob'),  // optional session binding
});
let bob = await initReceiverState({ sharedSecret, dhKeyPair: bobPair });

// Send. Note the shape: a NEW state comes back, the old one is untouched.
const { nextState, message } = await encryptMessage(alice, plaintextBytes);
await db.saveRatchetState(serializeRatchetState(nextState));
destroyRatchetState(alice);            // ← the step that buys forward secrecy
alice = nextState;

// Receive.
const received = await decryptMessage(bob, message);
await db.saveRatchetState(serializeRatchetState(received.nextState));
destroyRatchetState(bob);
bob = received.nextState;
```

The persistence contract is the whole game:

1. **Persist `nextState` before acting on the result.** If you save the old
   state, the session desynchronises.
2. **Destroy the state you replaced.** Holding it alive holds its chain keys
   alive, which is exactly what the ratchet exists to prevent.
3. **Never reuse a state for two messages.** Encrypting twice from the same
   state produces two messages at the same chain position — the second one
   will not decrypt.

Out-of-order and late messages are handled for you: keys for skipped
positions are retained in the state (capped at `maxSkippedKeys`, default
1000, oldest evicted first) and removed the moment they are used, so a
replayed message fails. A receiver cannot send until it has decrypted its
first inbound message — `encryptMessage` raises `DisInvalidArgumentError`
until then.

Every failure — forged ciphertext, altered header, altered counter, replay —
raises `DisDecryptionError` and leaves your input state untouched, so a
forged message cannot wedge a live session.

## 9. Error handling — what can go wrong

Always wrap DIS calls in a try/catch and map to user-facing copy. The
relevant errors are in `@msdis/shield/core`:

| Error | When | What to do |
| --- | --- | --- |
| `DisDecryptionError` | Wrong key, tampered ciphertext, or wrong AAD | Treat as "wrong password" or "data corruption". **Do not** expose the cause. |
| `DisIntegrityError` | SHA-256 verification of a stored payload failed | Treat as integrity violation. Trigger quarantine / re-fetch / log. |
| `DisUnsupportedFormatVersionError` | Ciphertext carries an unknown in-family version prefix | Refuse. Tell the user to update the app. |
| `DisLegacyPayloadError` | Runtime read hit an unversioned / no-AAD payload | Run the explicit migration path (see `docs/migrations.md`) or refuse. |
| `DisInvalidArgumentError` | Caller passed a bad argument (empty string, wrong length, etc.) | Treat as a programming error in the app. |
| `DisError('UNSUPPORTED_KDF_VERSION')` | Stored KDF version not in the registry | Same as `DisUnsupportedFormatVersionError`. |
| `DisError('KEY_DERIVATION_FAILED')` | Argon2id output was the wrong type | Should not happen; report as a bug. |
| `DisError('INVALID_ARGUMENT')` | Migration cycle detected | The migration registry has a bug; report. |

The contract: **AEAD failures do not reveal cause** (no padding/AAD oracle).
Your error UX must respect that.

## 10. Branding & UI Integration

According to the MauntingStudios Design DNA, applications utilizing DIS for security should display the standardized `DisBadge` element to indicate cryptographic integrity to the user.

```tsx
import { DisBadge } from '@msdis/shield/branding'; // or import from local Design DNA components

// Example: Floating bottom-right badge
export default function AppLayout() {
  return (
    <div className="relative min-h-screen">
      {/* Main content */}
      <main>...</main>
      
      {/* Floating DIS Badge */}
      <div className="fixed bottom-6 right-6 z-50">
        <DisBadge />
      </div>
    </div>
  );
}
```

The badge should ideally link to `https://dis.mauntingstudios.de` to give users access to the public documentation and security guarantees of the library.

## 11. What you should NOT do

- **Do not import `hash-wasm`, `otpauth`, or `@noble/post-quantum` directly.**
  These are pulled in transitively. Direct imports will be blocked by the
  consuming app's ESLint guardrail after the DIS cutover.
- **Do not call `crypto.subtle` directly in app code.** DIS provides a
  `getCryptoProvider()` / `setCryptoProvider()` seam if you need to swap the
  implementation in tests.
- **Do not store the master password, KDF output, content key, or wrapped
  private key on the server.** All of those belong client-side. The server
  stores only ciphertext, salts, wrapped keys, verification hashes, manifests.
- **Do not change a published envelope prefix.** Add a new version instead.
- **Do not roll your own KDF parameters.** Use the versioned registry.

## 12. Where to read more

- [`architecture.md`](architecture.md) — what DIS is and is not
- [`api-design.md`](api-design.md) — the supported function surface
- [`crypto-dependency-map.md`](crypto-dependency-map.md) — frozen wire-format
  constants, what apps still depend on
- [`trust-boundaries.md`](trust-boundaries.md) — what is in scope and out
- [`migrations.md`](migrations.md) — the migration framework
- [`threat-model.md`](threat-model.md), [`risk-analysis.md`](risk-analysis.md),
  [`crypto-review.md`](crypto-review.md) — the security analysis
