/**
 * dis-vault-crypto — the Singra Vault *application crypto profile*.
 *
 * This module is the stable, named API that Singra Vault (and, transitively,
 * Singra Premium) consume. It does NOT re-implement any primitive: every
 * operation is composed from the audited DIS modules (`kdf`, `aead`,
 * `vault-encryption`, `key-management`, `asymmetric`, `post-quantum`). What it
 * adds is the *application-specific composition and versioned envelope formats*
 * that Singra has always used:
 *
 *   - device-key strengthened Argon2id derivation (HKDF info `SINGRA_DEVICE_KEY_V1`)
 *   - the `sv-vault-v1:` vault-item envelope (entry-id AAD)
 *   - the two-tier UserKey model (`usk-wrap-v2:`) and private-key wrapping (`usk-v1:`)
 *   - sharing / emergency-access key material (`pq-v2:` hybrid keypair envelope)
 *   - KDF auto-upgrade, verification hashes, and re-encryption helpers
 *
 * Keeping these names and formats here means applications need ZERO crypto
 * code of their own — they import this profile and nothing else. Every byte
 * format is covered by golden-vector tests proving compatibility with the
 * pre-extraction Singra implementation.
 */

import { bytesToBase64, base64ToBytes } from '../core/encoding.js';
import {
    CURRENT_KDF_VERSION as DIS_CURRENT_KDF_VERSION,
    DEFAULT_KDF_PARAMS,
    deriveRawKey as disDeriveRawKey,
    generateSalt as disGenerateSalt,
    importAesGcmKey,
    type KdfParams as DisKdfParams,
} from '../kdf/index.js';
import {
    decryptBytes as disDecryptBytes,
    decryptString,
    encryptBytes as disEncryptBytes,
    encryptString,
} from '../aead/index.js';
import {
    decryptVaultEntry,
    decryptVaultEntryForMigration,
    encryptVaultEntry,
    isCurrentVaultEntryEnvelope,
    VAULT_ITEM_ENVELOPE_V1_PREFIX as DIS_VAULT_ITEM_ENVELOPE_V1_PREFIX,
    VAULT_ITEM_ENVELOPE_V2_PREFIX as DIS_VAULT_ITEM_ENVELOPE_V2_PREFIX,
} from '../vault-encryption/index.js';
import {
    createDeterministicWrappedUserKey,
    createWrappedUserKey,
    generateAesGcmKeyJwk,
    importAesGcmKeyFromJwk,
    rotateWrappedKey,
    unwrapUserKey as disUnwrapUserKey,
    unwrapUserKeyBytes as disUnwrapUserKeyBytes,
    type UserKeyBundle as DisUserKeyBundle,
} from '../key-management/index.js';
import {
    exportJwk,
    generateRsaOaepKeyPair,
    importRsaOaepPrivateKey,
    importRsaOaepPublicKey,
    rsaOaepDecrypt,
    rsaOaepEncrypt,
} from '../asymmetric/index.js';
import { generatePQKeyPair } from '../post-quantum/index.js';
import { SecureBuffer } from '../secure-memory/index.js';

// ============ Constants & format contract ============

/** The latest KDF version. Newly set-up accounts use this version. */
export const CURRENT_KDF_VERSION = DIS_CURRENT_KDF_VERSION;

/** Argon2id parameter set for a given KDF version. */
export type KdfParams = DisKdfParams;

/**
 * KDF parameter sets indexed by version number. Byte-compatible with Singra.
 * Exposed as a plain record for call sites that look up params by version.
 */
export const KDF_PARAMS: Record<number, KdfParams> = { ...DEFAULT_KDF_PARAMS };

/** Versioned envelope prefix for vault item payloads. */
export const VAULT_ITEM_ENVELOPE_V1_PREFIX = DIS_VAULT_ITEM_ENVELOPE_V1_PREFIX;
export const VAULT_ITEM_ENVELOPE_V2_PREFIX = DIS_VAULT_ITEM_ENVELOPE_V2_PREFIX;

/** HKDF `info` binding the derived key to a device key (second factor). */
const DEVICE_KEY_HKDF_INFO = 'SINGRA_DEVICE_KEY_V1';

/** Constant used in v3 verification hashes (no plaintext stored in DB). */
const VERIFICATION_CONSTANT_V3 = 'SINGRA_VAULT_VERIFY_V3';

/** Encrypted category field prefix used for category name/icon/color. */
const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';

/** Sentinel prefix for private keys wrapped under the UserKey. */
const USK_V1_PREFIX = 'usk-v1:';

/** Internal counter for legacy (no-AAD) decryption fallbacks (monitoring). */
let _legacyDecryptCount = 0;

export type UserKeyBundle = DisUserKeyBundle;

/** Sensitive vault item data that gets encrypted. */
export interface VaultItemData {
    title?: string;
    websiteUrl?: string;
    itemType?: 'password' | 'note' | 'totp' | 'card';
    isFavorite?: boolean;
    categoryId?: string | null;
    username?: string;
    password?: string;
    notes?: string;
    totpSecret?: string;
    totpIssuer?: string;
    totpLabel?: string;
    totpAlgorithm?: 'SHA1' | 'SHA256' | 'SHA512';
    totpDigits?: 6 | 8;
    totpPeriod?: number;
    customFields?: Record<string, string>;
    /** Internal marker for duress/decoy items (never exposed to UI). */
    _duress?: boolean;
}

// ============ Salt & KDF ============

/** Generates a cryptographically secure random salt (base64, 128-bit). */
export function generateSalt(): string {
    return disGenerateSalt();
}

function strengthenOptions(deviceKey?: Uint8Array) {
    return deviceKey ? { hkdfSalt: deviceKey, info: DEVICE_KEY_HKDF_INFO } : undefined;
}

/**
 * Derives raw AES-256 key bytes from a master password using Argon2id.
 * When a deviceKey is provided, the result is strengthened via HKDF-Expand
 * with the device key as salt. Caller owns/must wipe the returned buffer.
 */
export async function deriveRawKey(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<Uint8Array> {
    return disDeriveRawKey(masterPassword, saltBase64, {
        version: kdfVersion,
        strengthen: strengthenOptions(deviceKey),
    });
}

/**
 * Derives raw key bytes wrapped in a SecureBuffer for safer handling.
 * The SecureBuffer auto-zeros on destroy. Caller MUST call `.destroy()`.
 */
export async function deriveRawKeySecure(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<SecureBuffer> {
    const rawBytes = await deriveRawKey(masterPassword, saltBase64, kdfVersion, deviceKey);
    const secure = SecureBuffer.fromBytes(rawBytes);
    rawBytes.fill(0);
    return secure;
}

/** Derives an AES-256-GCM CryptoKey from a master password. */
export async function deriveKey(
    masterPassword: string,
    saltBase64: string,
    kdfVersion: number = CURRENT_KDF_VERSION,
    deviceKey?: Uint8Array,
): Promise<CryptoKey> {
    const keyBytes = await deriveRawKey(masterPassword, saltBase64, kdfVersion, deviceKey);
    try {
        return await importMasterKey(keyBytes);
    } finally {
        keyBytes.fill(0);
    }
}

/** Imports raw 256-bit key bytes into a non-extractable AES-GCM CryptoKey. */
export async function importMasterKey(keyBytes: Uint8Array | BufferSource): Promise<CryptoKey> {
    return importAesGcmKey(keyBytes);
}

// ============ AEAD (string + bytes) ============

/** Encrypts a UTF-8 string with AES-256-GCM. Optional AAD binds context. */
export async function encrypt(plaintext: string, key: CryptoKey, aad?: string): Promise<string> {
    return encryptString(plaintext, key, aad);
}

/** Encrypts binary data with AES-256-GCM. Caller owns/wipes `plaintextBytes`. */
export async function encryptBytes(
    plaintextBytes: Uint8Array,
    key: CryptoKey,
    aad?: string,
): Promise<string> {
    return disEncryptBytes(plaintextBytes, key, aad);
}

/** Decrypts AES-256-GCM data to a UTF-8 string. */
export async function decrypt(encryptedBase64: string, key: CryptoKey, aad?: string): Promise<string> {
    return decryptString(encryptedBase64, key, aad);
}

/** Decrypts AES-256-GCM data to plaintext bytes (secret — caller must wipe). */
export async function decryptBytes(
    encryptedBase64: string,
    key: CryptoKey,
    aad?: string,
): Promise<Uint8Array> {
    return disDecryptBytes(encryptedBase64, key, aad);
}

// ============ Vault item envelope ============

/** Encrypts a vault item, binding the ciphertext to `entryId` via AAD. */
export async function encryptVaultItem(
    data: VaultItemData,
    key: CryptoKey,
    entryId: string,
): Promise<string> {
    return encryptVaultEntry(data as Record<string, unknown>, key, entryId);
}

/**
 * Decrypts a vault item. Versioned payloads are read with `entryId` as AAD and
 * fail closed for the oldest no-AAD payloads unless the explicit migration
 * fallback is requested.
 */
export async function decryptVaultItem(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
    options: { allowLegacyNoAadFallback?: boolean } = {},
): Promise<VaultItemData> {
    if (options.allowLegacyNoAadFallback) {
        const result = await decryptVaultEntryForMigration(encryptedData, key, entryId);
        if (result.legacyNoAadFallbackUsed) {
            console.warn(`Legacy entry without AAD detected: ${entryId}`);
            _legacyDecryptCount++;
        }
        return result.data as VaultItemData;
    }
    return (await decryptVaultEntry(encryptedData, key, entryId)) as VaultItemData;
}

export interface VaultItemMigrationDecryptResult {
    data: VaultItemData;
    legacyEnvelopeUsed: boolean;
    legacyNoAadFallbackUsed: boolean;
}

/**
 * Decrypts an item only for an explicit migration path. Runtime reads must use
 * decryptVaultItem(), which fails closed for legacy no-AAD payloads.
 */
export async function decryptVaultItemForMigration(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<VaultItemMigrationDecryptResult> {
    const result = await decryptVaultEntryForMigration(encryptedData, key, entryId);
    if (result.legacyNoAadFallbackUsed) {
        console.warn(`Legacy entry without AAD detected: ${entryId}`);
        _legacyDecryptCount++;
    }
    return {
        data: result.data as VaultItemData,
        legacyEnvelopeUsed: result.legacyEnvelopeUsed,
        legacyNoAadFallbackUsed: result.legacyNoAadFallbackUsed,
    };
}

/**
 * True if `encryptedData` is a current versioned vault-item envelope.
 *
 * Fails closed (throws) on an unknown in-family version (`sv-vault-v<n>:`) so a
 * future format can never be silently treated as legacy by migration code —
 * matching the Singra contract. Callers that need a non-throwing predicate must
 * wrap this explicitly.
 */
export function isCurrentVaultItemEnvelope(encryptedData: string): boolean {
    return isCurrentVaultEntryEnvelope(encryptedData);
}

// ============ Verification hashes ============

/** Creates a password verification hash (v3: encrypts a known constant). */
export async function createVerificationHash(key: CryptoKey): Promise<string> {
    const encrypted = await encrypt(VERIFICATION_CONSTANT_V3, key);
    return `v3:${encrypted}`;
}

/** Verifies that `key` can decrypt the stored verification hash. */
export async function verifyKey(verificationHash: string, key: CryptoKey): Promise<boolean> {
    try {
        if (verificationHash.startsWith('v3:')) {
            const encrypted = verificationHash.slice(3);
            const decrypted = await decrypt(encrypted, key);
            return decrypted === VERIFICATION_CONSTANT_V3;
        }
        if (verificationHash.startsWith('v2:')) {
            const parts = verificationHash.split(':');
            if (parts.length !== 3) {
                return false;
            }
            const challenge = parts[1]!;
            const encryptedChallenge = parts[2]!;
            const decrypted = await decrypt(encryptedChallenge, key);
            return decrypted === challenge;
        }
        const decrypted = await decrypt(verificationHash, key);
        return decrypted === 'SINGRA_PW_VERIFICATION';
    } catch {
        return false;
    }
}

// ============ KDF auto-migration ============

export interface KdfUpgradeResult {
    upgraded: boolean;
    newKey?: CryptoKey;
    oldKey?: CryptoKey;
    newVerifier?: string;
    activeVersion: number;
    newEncryptedUserKey?: string;
}

/**
 * Attempts to upgrade KDF parameters to the latest version after unlock.
 * USK path only re-wraps the 32-byte UserKey (no vault re-encryption). Legacy
 * path returns old+new keys so the caller can re-encrypt vault data.
 */
export async function attemptKdfUpgrade(
    masterPassword: string,
    saltBase64: string,
    currentVersion: number,
    deviceKey?: Uint8Array,
    encryptedUserKey?: string,
    existingKdfOutputBytes?: Uint8Array,
): Promise<KdfUpgradeResult> {
    if (currentVersion >= CURRENT_KDF_VERSION) {
        return { upgraded: false, activeVersion: currentVersion };
    }

    try {
        if (encryptedUserKey) {
            const ownedOldBytes = existingKdfOutputBytes
                ? null
                : await deriveRawKey(masterPassword, saltBase64, currentVersion, deviceKey);
            const oldKdfOutputBytes = existingKdfOutputBytes ?? ownedOldBytes!;
            const newKdfOutputBytes = await deriveRawKey(
                masterPassword,
                saltBase64,
                CURRENT_KDF_VERSION,
                deviceKey,
            );
            try {
                const newEncryptedUserKey = await rewrapUserKey(
                    encryptedUserKey,
                    oldKdfOutputBytes,
                    newKdfOutputBytes,
                );
                const newUserKey = await unwrapUserKey(newEncryptedUserKey, newKdfOutputBytes);
                const newVerifier = await createVerificationHash(newUserKey);
                return {
                    upgraded: true,
                    newVerifier,
                    newEncryptedUserKey,
                    activeVersion: CURRENT_KDF_VERSION,
                };
            } finally {
                ownedOldBytes?.fill(0);
                newKdfOutputBytes.fill(0);
            }
        }

        const newKey = await deriveKey(masterPassword, saltBase64, CURRENT_KDF_VERSION, deviceKey);
        const oldKey = await deriveKey(masterPassword, saltBase64, currentVersion, deviceKey);
        const newVerifier = await createVerificationHash(newKey);
        return { upgraded: true, newKey, oldKey, newVerifier, activeVersion: CURRENT_KDF_VERSION };
    } catch (err) {
        console.warn(
            `KDF upgrade from v${currentVersion} to v${CURRENT_KDF_VERSION} failed (likely OOM), staying on v${currentVersion}:`,
            err,
        );
        return { upgraded: false, activeVersion: currentVersion };
    }
}

// ============ Vault re-encryption ============

/** Re-encrypts a single encrypted string from oldKey to newKey. */
export async function reEncryptString(
    encryptedBase64: string,
    oldKey: CryptoKey,
    newKey: CryptoKey,
    aad?: string,
): Promise<string> {
    let plaintext: string;
    if (aad) {
        try {
            plaintext = await decrypt(encryptedBase64, oldKey, aad);
        } catch {
            plaintext = await decrypt(encryptedBase64, oldKey);
        }
    } else {
        plaintext = await decrypt(encryptedBase64, oldKey);
    }
    return encrypt(plaintext, newKey, aad);
}

export interface ReEncryptionResult {
    itemsReEncrypted: number;
    categoriesReEncrypted: number;
    itemUpdates: Array<{ id: string; encrypted_data: string }>;
    categoryUpdates: Array<{ id: string; name: string; icon: string | null; color: string | null }>;
    legacyItemsFound: number;
}

/**
 * Re-encrypts all vault items and encrypted category fields from an old key to
 * a new key (required during KDF upgrades). Pure: no DB side effects.
 */
export async function reEncryptVault(
    items: Array<{ id: string; encrypted_data: string }>,
    categories: Array<{ id: string; name: string; icon: string | null; color: string | null }>,
    oldKey: CryptoKey,
    newKey: CryptoKey,
): Promise<ReEncryptionResult> {
    const itemUpdates: Array<{ id: string; encrypted_data: string }> = [];
    for (const item of items) {
        try {
            const plaintext = await decryptVaultItem(item.encrypted_data, oldKey, item.id, {
                allowLegacyNoAadFallback: true,
            });
            const newEncrypted = await encryptVaultItem(plaintext, newKey, item.id);
            itemUpdates.push({ id: item.id, encrypted_data: newEncrypted });
        } catch (err) {
            throw new Error(`Failed to re-encrypt vault item ${item.id}: ${err}`);
        }
    }

    const categoryUpdates: Array<{
        id: string;
        name: string;
        icon: string | null;
        color: string | null;
    }> = [];
    for (const cat of categories) {
        let newName = cat.name;
        let newIcon = cat.icon;
        let newColor = cat.color;
        let changed = false;

        if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newName = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category name ${cat.id}: ${err}`);
            }
        }

        if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newIcon = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category icon ${cat.id}: ${err}`);
            }
        }

        if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
            try {
                const encPart = cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length);
                const reEncrypted = await reEncryptString(encPart, oldKey, newKey);
                newColor = `${ENCRYPTED_CATEGORY_PREFIX}${reEncrypted}`;
                changed = true;
            } catch (err) {
                throw new Error(`Failed to re-encrypt category color ${cat.id}: ${err}`);
            }
        }

        if (changed) {
            categoryUpdates.push({ id: cat.id, name: newName, icon: newIcon, color: newColor });
        }
    }

    const legacyFound = _legacyDecryptCount;
    _legacyDecryptCount = 0;

    return {
        itemsReEncrypted: itemUpdates.length,
        categoriesReEncrypted: categoryUpdates.length,
        itemUpdates,
        categoryUpdates,
        legacyItemsFound: legacyFound,
    };
}

// ============ Vault item data helpers ============

/**
 * Clears sensitive references from a VaultItemData object. NOTE: JS strings are
 * immutable; this only drops references so the GC can reclaim them sooner.
 */
export function clearReferences(data: VaultItemData): void {
    if (data.title) data.title = '';
    if (data.websiteUrl) data.websiteUrl = '';
    if (data.itemType) data.itemType = 'password';
    if (typeof data.isFavorite === 'boolean') data.isFavorite = false;
    if (typeof data.categoryId !== 'undefined') data.categoryId = null;
    if (data.username) data.username = '';
    if (data.password) data.password = '';
    if (data.notes) data.notes = '';
    if (data.totpSecret) data.totpSecret = '';
    if (data.totpIssuer) data.totpIssuer = '';
    if (data.totpLabel) data.totpLabel = '';
    if (data.customFields) {
        Object.keys(data.customFields).forEach((key) => {
            data.customFields![key] = '';
        });
    }
}

/** @deprecated Use clearReferences. secureClear implies wiping JS cannot do. */
export const secureClear = clearReferences;

// ============ Asymmetric (RSA-OAEP) for emergency access ============

export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
    return generateRsaOaepKeyPair();
}

export async function exportPublicKey(key: CryptoKey): Promise<JsonWebKey> {
    return exportJwk(key);
}

export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return importRsaOaepPublicKey(jwk);
}

export async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return importRsaOaepPrivateKey(jwk);
}

export async function exportPrivateKey(key: CryptoKey): Promise<JsonWebKey> {
    return exportJwk(key);
}

export async function encryptRSA(plaintext: string, publicKey: CryptoKey): Promise<string> {
    return rsaOaepEncrypt(plaintext, publicKey);
}

export async function decryptRSA(ciphertextBase64: string, privateKey: CryptoKey): Promise<string> {
    return rsaOaepDecrypt(ciphertextBase64, privateKey);
}

// ============ Shared-collection key material ============

/**
 * Generates a user's asymmetric key material for shared collections.
 * v1: RSA-only wrapping. v2: hybrid PQ+RSA (`pq-v2:` envelope).
 */
export async function generateUserKeyPair(
    masterPassword: string,
    version: 1 | 2 = 2,
): Promise<{ publicKey: string; encryptedPrivateKey: string; pqPublicKey?: string }> {
    if (version === 1) {
        const keyPair = await generateRsaOaepKeyPair();
        const publicKey = JSON.stringify(await exportJwk(keyPair.publicKey));
        const privateKey = JSON.stringify(await exportJwk(keyPair.privateKey));

        const salt = generateSalt();
        const kdfVersion = CURRENT_KDF_VERSION;
        const key = await deriveKey(masterPassword, salt, kdfVersion);
        const encryptedPrivateKey = await encrypt(privateKey, key);

        return {
            publicKey,
            encryptedPrivateKey: `${kdfVersion}:${salt}:${encryptedPrivateKey}`,
        };
    }

    // Version 2: hybrid PQ+RSA wrapping (ML-KEM-768 + RSA-4096).
    const rsaKeyPair = await generateRsaOaepKeyPair();
    const pqKeyPair = generatePQKeyPair();
    const { publicKey: pqPublicKeyBase64, secretKey: pqSecretKeyBase64 } = pqKeyPair;

    const rsaPublicKey = JSON.stringify(await exportJwk(rsaKeyPair.publicKey));
    const rsaPrivateKey = JSON.stringify(await exportJwk(rsaKeyPair.privateKey));

    const salt = generateSalt();
    const kdfVersion = CURRENT_KDF_VERSION;
    const key = await deriveKey(masterPassword, salt, kdfVersion);

    const encryptedRsaKey = await encrypt(rsaPrivateKey, key);
    const encryptedPqKey = await encrypt(pqSecretKeyBase64, key);

    const encryptedPrivateKey = `pq-v2:${kdfVersion}:${salt}:${encryptedRsaKey}:${encryptedPqKey}`;

    return { publicKey: rsaPublicKey, encryptedPrivateKey, pqPublicKey: pqPublicKeyBase64 };
}

/** Migrates RSA-only wrapping key material to hybrid PQ+RSA key material. */
export async function migrateToHybridKeyPair(
    encryptedPrivateKey: string,
    masterPassword: string,
): Promise<{ publicKey: string; encryptedPrivateKey: string; pqPublicKey: string } | null> {
    try {
        if (encryptedPrivateKey.startsWith('pq-v2:')) {
            return null;
        }

        const parts = encryptedPrivateKey.split(':');
        let kdfVersion = 1;
        let salt: string;
        let encryptedData: string;

        if (parts.length === 2) {
            salt = parts[0]!;
            encryptedData = parts[1]!;
        } else if (parts.length === 3) {
            kdfVersion = parseInt(parts[0]!, 10);
            salt = parts[1]!;
            encryptedData = parts[2]!;
        } else {
            throw new Error('Invalid encrypted private key format');
        }

        const key = await deriveKey(masterPassword, salt, kdfVersion);
        const rsaPrivateKey = await decrypt(encryptedData, key);

        const rsaPrivateKeyJwk = JSON.parse(rsaPrivateKey) as Record<string, unknown>;
        const rsaPublicKeyJwk = {
            ...rsaPrivateKeyJwk,
            d: undefined,
            dp: undefined,
            dq: undefined,
            p: undefined,
            q: undefined,
            qi: undefined,
            key_ops: ['encrypt'],
        };
        const rsaPublicKey = JSON.stringify(rsaPublicKeyJwk);

        const pqKeyPair = generatePQKeyPair();
        const { publicKey: pqPublicKey, secretKey: pqSecretKey } = pqKeyPair;

        const newSalt = generateSalt();
        const newKdfVersion = CURRENT_KDF_VERSION;
        const newKey = await deriveKey(masterPassword, newSalt, newKdfVersion);

        const encryptedRsaKey = await encrypt(rsaPrivateKey, newKey);
        const encryptedPqKey = await encrypt(pqSecretKey, newKey);

        const hybridEncryptedKey = `pq-v2:${newKdfVersion}:${newSalt}:${encryptedRsaKey}:${encryptedPqKey}`;

        return { publicKey: rsaPublicKey, encryptedPrivateKey: hybridEncryptedKey, pqPublicKey };
    } catch (err) {
        console.error('Failed to migrate to hybrid key pair:', err);
        return null;
    }
}

/** Generates a random shared encryption key for a collection (AES-256 JWK). */
export async function generateSharedKey(): Promise<string> {
    return generateAesGcmKeyJwk();
}

/** Encrypts vault item data with a shared key. Optional AAD binds context. */
export async function encryptWithSharedKey(
    data: VaultItemData,
    sharedKey: string,
    aad?: string,
): Promise<string> {
    const key = await importAesGcmKeyFromJwk(sharedKey, ['encrypt']);
    return encrypt(JSON.stringify(data), key, aad);
}

export interface SharedKeyDecryptOptions {
    /** Allows reading pre-AAD shared ciphertexts during explicit migration only. */
    allowLegacyNoAadFallback?: boolean;
}

/** Decrypts vault item data with a shared key. Fails closed by default. */
export async function decryptWithSharedKey(
    encryptedData: string,
    sharedKey: string,
    aad?: string,
    options: SharedKeyDecryptOptions = {},
): Promise<VaultItemData> {
    const key = await importAesGcmKeyFromJwk(sharedKey, ['decrypt']);
    let json: string;
    if (aad) {
        try {
            json = await decrypt(encryptedData, key, aad);
        } catch {
            if (!options.allowLegacyNoAadFallback) {
                throw new Error('Shared item decryption failed with the required AAD context.');
            }
            _legacyDecryptCount++;
            json = await decrypt(encryptedData, key);
        }
    } else {
        json = await decrypt(encryptedData, key);
    }
    return JSON.parse(json) as VaultItemData;
}

// ============ User Symmetric Key (USK) layer ============

/** Creates a new random UserKey wrapped under a KEK from the KDF output. */
export async function createEncryptedUserKey(kdfOutputBytes: Uint8Array): Promise<UserKeyBundle> {
    return createWrappedUserKey(kdfOutputBytes);
}

/** Derives a deterministic UserKey from the KDF output and wraps it (migration). */
export async function migrateToUserKey(kdfOutputBytes: Uint8Array): Promise<UserKeyBundle> {
    return createDeterministicWrappedUserKey(kdfOutputBytes);
}

/** Decrypts the stored encryptedUserKey to obtain the UserKey CryptoKey. */
export async function unwrapUserKey(
    encryptedUserKey: string,
    kdfOutputBytes: Uint8Array,
): Promise<CryptoKey> {
    return disUnwrapUserKey(encryptedUserKey, kdfOutputBytes);
}

/** Decrypts the stored encryptedUserKey and returns the raw UserKey bytes. */
export async function unwrapUserKeyBytes(
    encryptedUserKey: string,
    kdfOutputBytes: Uint8Array,
): Promise<Uint8Array> {
    return disUnwrapUserKeyBytes(encryptedUserKey, kdfOutputBytes);
}

/** Re-wraps an existing UserKey under a new KDF output. UserKey unchanged. */
export async function rewrapUserKey(
    encryptedUserKey: string,
    oldKdfOutputBytes: Uint8Array,
    newKdfOutputBytes: Uint8Array,
): Promise<string> {
    return rotateWrappedKey(encryptedUserKey, oldKdfOutputBytes, newKdfOutputBytes);
}

/** Encrypts a private key (RSA JWK / PQ base64) with the UserKey (`usk-v1:`). */
export async function wrapPrivateKeyWithUserKey(
    privateKeyMaterial: string,
    userKey: CryptoKey,
): Promise<string> {
    const enc = await encrypt(privateKeyMaterial, userKey);
    return `${USK_V1_PREFIX}${enc}`;
}

/** Decrypts a private key wrapped with wrapPrivateKeyWithUserKey. */
export async function unwrapPrivateKeyWithUserKey(
    wrappedKey: string,
    userKey: CryptoKey,
): Promise<string> {
    if (!wrappedKey.startsWith(USK_V1_PREFIX)) {
        throw new Error('unwrapPrivateKeyWithUserKey: unexpected format (missing usk-v1: prefix)');
    }
    return decrypt(wrappedKey.slice(USK_V1_PREFIX.length), userKey);
}

/**
 * Decrypts a legacy private key encrypted with its own KDF derivation.
 * Handles `kdfVersion:salt:enc`, `salt:enc`, and `pq-v2:kdfVersion:salt:encRsa:encPq`.
 */
export async function decryptPrivateKeyLegacy(
    encryptedPrivateKey: string,
    masterPassword: string,
    extractPqPart = false,
): Promise<string> {
    if (encryptedPrivateKey.startsWith('pq-v2:')) {
        const rest = encryptedPrivateKey.slice('pq-v2:'.length);
        const colonIdx1 = rest.indexOf(':');
        const colonIdx2 = rest.indexOf(':', colonIdx1 + 1);
        const colonIdx3 = rest.indexOf(':', colonIdx2 + 1);
        if (colonIdx1 < 0 || colonIdx2 < 0 || colonIdx3 < 0) {
            throw new Error('decryptPrivateKeyLegacy: invalid pq-v2 format');
        }
        const kdfVersion = parseInt(rest.slice(0, colonIdx1), 10);
        const salt = rest.slice(colonIdx1 + 1, colonIdx2);
        const encRsaKey = rest.slice(colonIdx2 + 1, colonIdx3);
        const encPqKey = rest.slice(colonIdx3 + 1);
        const key = await deriveKey(masterPassword, salt, kdfVersion);
        return extractPqPart ? decrypt(encPqKey, key) : decrypt(encRsaKey, key);
    }

    const parts = encryptedPrivateKey.split(':');
    let kdfVersion = 1;
    let salt: string;
    let encData: string;

    if (parts.length === 2) {
        salt = parts[0]!;
        encData = parts[1]!;
    } else if (parts.length === 3) {
        kdfVersion = parseInt(parts[0]!, 10);
        salt = parts[1]!;
        encData = parts[2]!;
    } else {
        throw new Error(
            `decryptPrivateKeyLegacy: unrecognised format (${parts.length} colon-separated parts)`,
        );
    }

    const key = await deriveKey(masterPassword, salt, kdfVersion);
    return decrypt(encData, key);
}

/** Decrypts a stored RSA private key, dispatching on format sentinel. */
export async function getDecryptedRsaPrivateKey(
    encryptedPrivateKey: string,
    userKey: CryptoKey | null,
    masterPassword: string,
): Promise<string> {
    if (encryptedPrivateKey.startsWith(USK_V1_PREFIX)) {
        if (!userKey) {
            throw new Error('getDecryptedRsaPrivateKey: UserKey required for usk-v1 format');
        }
        return unwrapPrivateKeyWithUserKey(encryptedPrivateKey, userKey);
    }
    return decryptPrivateKeyLegacy(encryptedPrivateKey, masterPassword, false);
}

/** Decrypts a stored PQ (ML-KEM-768) private key, dispatching on format sentinel. */
export async function getDecryptedPqPrivateKey(
    encryptedPqPrivateKey: string,
    userKey: CryptoKey | null,
    masterPassword: string,
): Promise<string> {
    if (encryptedPqPrivateKey.startsWith(USK_V1_PREFIX)) {
        if (!userKey) {
            throw new Error('getDecryptedPqPrivateKey: UserKey required for usk-v1 format');
        }
        return unwrapPrivateKeyWithUserKey(encryptedPqPrivateKey, userKey);
    }
    if (encryptedPqPrivateKey.startsWith('pq-v2:')) {
        return decryptPrivateKeyLegacy(encryptedPqPrivateKey, masterPassword, true);
    }
    return decryptPrivateKeyLegacy(encryptedPqPrivateKey, masterPassword, false);
}

// Internal: base64 helpers exposed for adapters that round-trip raw bytes.
export { bytesToBase64, base64ToBytes };
