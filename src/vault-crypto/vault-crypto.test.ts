/**
 * Singra Vault application-profile tests.
 *
 * Two guarantees are asserted here:
 *   1. BYTE-COMPAT: the profile reads the exact legacy golden vectors (produced
 *      by the pre-extraction in-tree Singra cryptoService) through its public
 *      API — proving the composition delegates to the proven primitives without
 *      altering any wire format.
 *   2. ROUND-TRIP: every profile-only format (verification hash, UserKey wrap,
 *      `usk-v1:` private-key wrap, `pq-v2:` hybrid keypair envelope, shared key,
 *      RSA-OAEP, KDF upgrade, re-encryption) seals and opens correctly and fails
 *      closed on tampering / wrong context.
 */
import { describe, expect, it, vi } from 'vitest';
import * as vault from './index.js';

const PW = 'correct horse battery staple';
const SALT = 'ZGV0ZXJtaW5pc3RpYy1zYWx0LTE2Qg==';

const b64ToBytes = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, 'base64'));

describe('Singra profile — legacy golden vectors (byte-compat via profile API)', () => {
    it('KDF: profile.deriveRawKey reproduces legacy Argon2id bytes (v1, v2)', async () => {
        const vectors: Record<1 | 2, string> = {
            1: '1ehUGlF3Tb7w90vk/872uy/4uLebUW/Vzz6b6eAoGiM=',
            2: 'SF/WwUBBYz38cCp0KAmtN0dPq+O5lpGfFs5I89HfWZI=',
        };
        for (const version of [1, 2] as const) {
            const raw = await vault.deriveRawKey(PW, SALT, version);
            expect([...raw]).toEqual([...b64ToBytes(vectors[version])]);
            raw.fill(0);
        }
    });

    it('AEAD: profile.decrypt opens legacy ciphertext (with + without AAD)', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const withAad = '1lXWfk5cncBHIX2ntRh54N0TiwIkNL0WNdA4m2vM/6fQI/wcAw==';
        const noAad = 'GOi+biTwduypJ/A9MCzWWgV3UuS0gWkQd/KZGbdLx7FB/C7nzDPUOdny3uI=';
        expect(await vault.decrypt(withAad, key, 'aad-1')).toBe('hello DIS');
        expect(await vault.decrypt(noAad, key)).toBe('hello DIS no aad');
    });

    it('Vault item: profile.decryptVaultItem opens the legacy sv-vault-v1 envelope', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const entryId = '11111111-1111-4111-8111-111111111111';
        const sealed =
            'sv-vault-v1:nOVpHlEQUrM/okRGd9iJZU/LyfYx5A0a3VAzAbjRWNhutkew4vmfTZML4oUTbJChb4pNblxsEE/mLRAuJJl0KgHmuFhM+bH1CPFDLBwokh8=';
        expect(await vault.decryptVaultItem(sealed, key, entryId)).toEqual({
            username: 'alice',
            password: 's3cret',
            notes: 'n',
        });
    });

    it('UserKey: profile.unwrapUserKeyBytes opens the legacy usk-wrap-v2 bundle', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const encryptedUserKey =
            'usk-wrap-v2:OcV0IQUJiYf5E3f1a144DuFJnoy8l6cSx2tyfl09GZED0iwWm5A96tkMyq6+3G/Ao6TQw/GBNGw7UK06';
        const userKey = await vault.unwrapUserKeyBytes(encryptedUserKey, kdfOut);
        expect(userKey.length).toBe(32);
        kdfOut.fill(0);
        userKey.fill(0);
    });
});

describe('Singra profile — vault item round-trip & fail-closed', () => {
    it('seals and opens a vault item bound to its entry id', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const entryId = 'entry-abc';
        const data: vault.VaultItemData = { username: 'bob', password: 'hunter2', notes: 'x' };
        const sealed = await vault.encryptVaultItem(data, key, entryId);
        expect(vault.isCurrentVaultItemEnvelope(sealed)).toBe(true);
        expect(await vault.decryptVaultItem(sealed, key, entryId)).toEqual(data);
    });

    it('fails closed when the entry id (AAD) does not match', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const sealed = await vault.encryptVaultItem({ password: 'p' }, key, 'entry-1');
        await expect(vault.decryptVaultItem(sealed, key, 'entry-2')).rejects.toThrow();
    });

    it('isCurrentVaultItemEnvelope: true for v2, false for v1 and legacy, THROWS for unknown sv-vault-*', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const sealed = await vault.encryptVaultItem({ password: 'p' }, key, 'e');
        expect(vault.isCurrentVaultItemEnvelope(sealed)).toBe(true);

        const v1Payload = await vault.encrypt(JSON.stringify({ password: 'p' }), key, 'e');
        const v1 = `${vault.VAULT_ITEM_ENVELOPE_V1_PREFIX}${v1Payload}`;
        expect(vault.isCurrentVaultItemEnvelope(v1)).toBe(false);
        expect(await vault.decryptVaultItem(v1, key, 'e')).toEqual({ password: 'p' });

        expect(vault.isCurrentVaultItemEnvelope('bGVnYWN5LWJhc2U2NA==')).toBe(false);
        expect(() => vault.isCurrentVaultItemEnvelope('sv-vault-v99:future-payload')).toThrow(
            /Unsupported vault item encryption envelope version/,
        );
    });

    it('decryptVaultItem warns + opens legacy no-AAD payloads only under explicit migration', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const item = { title: 'legacy', password: 'secret' };
        const legacyNoAad = await vault.encrypt(JSON.stringify(item), key); // no envelope, no AAD
        // Runtime read path fails closed.
        await expect(vault.decryptVaultItem(legacyNoAad, key, 'item-1')).rejects.toThrow();
        // Explicit migration path opens it AND logs the legacy marker.
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        await expect(
            vault.decryptVaultItem(legacyNoAad, key, 'item-1', { allowLegacyNoAadFallback: true }),
        ).resolves.toEqual(item);
        expect(warn).toHaveBeenCalledWith(expect.stringContaining('Legacy entry without AAD detected'));
        warn.mockRestore();
    });
});

describe('Singra profile — re-encryption helper', () => {
    it('re-encrypts from an old key to a new key and rejects the wrong old key', async () => {
        const oldKey = await vault.deriveKey(PW, SALT, 1);
        const newKey = await vault.deriveKey(PW, SALT, 2);
        const sealed = await vault.encrypt('payload', oldKey, 'entry-1');

        const reEncrypted = await vault.reEncryptString(sealed, oldKey, newKey, 'entry-1');
        expect(await vault.decrypt(reEncrypted, newKey, 'entry-1')).toBe('payload');

        await expect(
            vault.reEncryptString(sealed, newKey, newKey, 'entry-1'),
        ).rejects.toThrow();
    });
});

describe('Singra profile — UserKey (USK) lifecycle', () => {
    it('creates, unwraps, and rotates a wrapped UserKey without re-encrypting data', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);
        expect(bundle.encryptedUserKey.startsWith('usk-wrap-v2:')).toBe(true);

        // Seal a vault item under the UserKey.
        const entryId = 'item-1';
        const sealed = await vault.encryptVaultItem({ password: 'pw' }, bundle.userKey, entryId);

        // Rotate to a new KDF output (e.g. password change) — data unchanged.
        const newKdfOut = await vault.deriveRawKey('new master pw', SALT, 2);
        const rewrapped = await vault.rewrapUserKey(bundle.encryptedUserKey, kdfOut, newKdfOut);
        const userKeyAfter = await vault.unwrapUserKey(rewrapped, newKdfOut);
        expect(await vault.decryptVaultItem(sealed, userKeyAfter, entryId)).toEqual({ password: 'pw' });

        kdfOut.fill(0);
        newKdfOut.fill(0);
    });

    it('migrateToUserKey derives a deterministic UserKey equal to the KDF output', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.migrateToUserKey(kdfOut);
        const recovered = await vault.unwrapUserKeyBytes(bundle.encryptedUserKey, kdfOut);
        expect([...recovered]).toEqual([...kdfOut]);
        kdfOut.fill(0);
        recovered.fill(0);
    });
});

describe('Singra profile — private key wrapping (usk-v1)', () => {
    it('wraps and unwraps a private key with the UserKey', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);
        const material = JSON.stringify({ kty: 'oct', k: 'secret-private-key-material' });

        const wrapped = await vault.wrapPrivateKeyWithUserKey(material, bundle.userKey);
        expect(wrapped.startsWith('usk-v1:')).toBe(true);
        expect(await vault.unwrapPrivateKeyWithUserKey(wrapped, bundle.userKey)).toBe(material);

        // Dispatch helper recognises the usk-v1 sentinel.
        expect(await vault.getDecryptedRsaPrivateKey(wrapped, bundle.userKey, PW)).toBe(material);
        kdfOut.fill(0);
    });
});

describe('Singra profile — sharing key material', () => {
    it('generateUserKeyPair v1 (RSA) → recover private key by master password', async () => {
        const { publicKey, encryptedPrivateKey } = await vault.generateUserKeyPair(PW, 1);
        expect(encryptedPrivateKey).not.toContain('pq-v2:');

        const recoveredPriv = await vault.getDecryptedRsaPrivateKey(encryptedPrivateKey, null, PW);
        // The recovered private JWK can decrypt what the public key encrypts.
        const pub = await vault.importPublicKey(JSON.parse(publicKey) as JsonWebKey);
        const priv = await vault.importPrivateKey(JSON.parse(recoveredPriv) as JsonWebKey);
        const ct = await vault.encryptRSA('shared-secret', pub);
        expect(await vault.decryptRSA(ct, priv)).toBe('shared-secret');
    }, 30_000);

    it('generateUserKeyPair v2 (hybrid pq-v2) → recover both RSA and PQ private keys', async () => {
        const { publicKey, encryptedPrivateKey, pqPublicKey } = await vault.generateUserKeyPair(PW, 2);
        expect(encryptedPrivateKey.startsWith('pq-v2:')).toBe(true);
        expect(typeof pqPublicKey).toBe('string');

        const rsaPriv = await vault.getDecryptedRsaPrivateKey(encryptedPrivateKey, null, PW);
        const pqPriv = await vault.getDecryptedPqPrivateKey(encryptedPrivateKey, null, PW);

        const pub = await vault.importPublicKey(JSON.parse(publicKey) as JsonWebKey);
        const priv = await vault.importPrivateKey(JSON.parse(rsaPriv) as JsonWebKey);
        const ct = await vault.encryptRSA('hybrid-secret', pub);
        expect(await vault.decryptRSA(ct, priv)).toBe('hybrid-secret');

        // PQ secret key is recoverable base64 material (length > 0).
        expect(pqPriv.length).toBeGreaterThan(0);
    }, 30_000);

    it('shared key seals and opens vault item data; fails closed on AAD mismatch', async () => {
        const sharedKey = await vault.generateSharedKey();
        const data: vault.VaultItemData = { username: 'u', password: 'p' };
        const sealed = await vault.encryptWithSharedKey(data, sharedKey, 'collection-item-1');
        expect(await vault.decryptWithSharedKey(sealed, sharedKey, 'collection-item-1')).toEqual(data);
        await expect(vault.decryptWithSharedKey(sealed, sharedKey, 'wrong-aad')).rejects.toThrow();
    });
});

describe('Singra profile — verification hash', () => {
    it('round-trips a v3 verification hash and rejects the wrong key', async () => {
        const key = await vault.deriveKey(PW, SALT, 2);
        const wrongKey = await vault.deriveKey('wrong', SALT, 2);
        const hash = await vault.createVerificationHash(key);
        expect(hash.startsWith('v3:')).toBe(true);
        expect(await vault.verifyKey(hash, key)).toBe(true);
        expect(await vault.verifyKey(hash, wrongKey)).toBe(false);
    });
});

describe('Singra profile — KDF upgrade & re-encryption', () => {
    it('attemptKdfUpgrade (USK path) rewraps the key and produces a working verifier', async () => {
        // Establish a v1 UserKey, then upgrade to current (v2).
        const oldKdfOut = await vault.deriveRawKey(PW, SALT, 1);
        const bundle = await vault.createEncryptedUserKey(oldKdfOut);

        const result = await vault.attemptKdfUpgrade(PW, SALT, 1, undefined, bundle.encryptedUserKey);
        expect(result.upgraded).toBe(true);
        expect(result.activeVersion).toBe(vault.CURRENT_KDF_VERSION);
        expect(result.newEncryptedUserKey).toBeDefined();

        const newKdfOut = await vault.deriveRawKey(PW, SALT, vault.CURRENT_KDF_VERSION);
        const userKey = await vault.unwrapUserKey(result.newEncryptedUserKey!, newKdfOut);
        expect(await vault.verifyKey(result.newVerifier!, userKey)).toBe(true);
        oldKdfOut.fill(0);
        newKdfOut.fill(0);
    });

    it('reEncryptVault migrates items from an old key to a new key', async () => {
        const oldKey = await vault.deriveKey(PW, SALT, 1);
        const newKey = await vault.deriveKey(PW, SALT, 2);
        const items = [
            { id: 'a', encrypted_data: await vault.encryptVaultItem({ password: '1' }, oldKey, 'a') },
            { id: 'b', encrypted_data: await vault.encryptVaultItem({ password: '2' }, oldKey, 'b') },
        ];
        const out = await vault.reEncryptVault(items, [], oldKey, newKey);
        expect(out.itemsReEncrypted).toBe(2);
        for (const upd of out.itemUpdates) {
            const data = await vault.decryptVaultItem(upd.encrypted_data, newKey, upd.id);
            expect(data.password).toBe(upd.id === 'a' ? '1' : '2');
        }
    });
});

describe('Singra profile — RSA-OAEP interop', () => {
    it('generates, exports/imports JWK, and round-trips RSA-OAEP', async () => {
        const pair = await vault.generateRSAKeyPair();
        const pubJwk = await vault.exportPublicKey(pair.publicKey);
        const privJwk = await vault.exportPrivateKey(pair.privateKey);
        const pub = await vault.importPublicKey(pubJwk);
        const priv = await vault.importPrivateKey(privJwk);
        const ct = await vault.encryptRSA('rsa-payload', pub);
        expect(await vault.decryptRSA(ct, priv)).toBe('rsa-payload');
    }, 30_000);
});
