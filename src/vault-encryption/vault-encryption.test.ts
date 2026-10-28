import { describe, expect, it } from 'vitest';
import {
    VAULT_ITEM_ENVELOPE_V1_PREFIX,
    VAULT_ITEM_ENVELOPE_V2_PREFIX,
    decryptVaultEntry,
    decryptVaultEntryForMigration,
    encryptVaultEntry,
    getVaultEntryEnvelopeVersion,
    isCurrentVaultEntryEnvelope,
    openVaultEntryString,
    sealVaultEntryString,
} from './index.js';
import { encryptString } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import { DisLegacyPayloadError, DisUnsupportedFormatVersionError } from '../core/errors.js';

async function freshKey(): Promise<CryptoKey> {
    return importAesGcmKey(randomBytes(32));
}

describe('vault entry encryption', () => {
    it('round-trips structured data and uses the v2 envelope', async () => {
        const key = await freshKey();
        const data = { username: 'alice', password: 'p@ss', notes: 'x' };
        const sealed = await encryptVaultEntry(data, key, 'entry-1');
        expect(sealed.startsWith(VAULT_ITEM_ENVELOPE_V2_PREFIX)).toBe(true);
        expect(getVaultEntryEnvelopeVersion(sealed)).toBe(2);
        expect(isCurrentVaultEntryEnvelope(sealed)).toBe(true);
        expect(await decryptVaultEntry(sealed, key, 'entry-1')).toEqual(data);
    });

    it('binds ciphertext to entryId (defeats swap attacks)', async () => {
        const key = await freshKey();
        const sealed = await encryptVaultEntry({ a: 1 }, key, 'entry-1');
        await expect(decryptVaultEntry(sealed, key, 'entry-2')).rejects.toBeTruthy();
    });

    it('reads a v1 envelope written by the old code', async () => {
        const key = await freshKey();
        const data = { username: 'legacy' };
        const payload = await encryptString(JSON.stringify(data), key, 'entry-1');
        const v1 = `${VAULT_ITEM_ENVELOPE_V1_PREFIX}${payload}`;
        expect(getVaultEntryEnvelopeVersion(v1)).toBe(1);
        expect(isCurrentVaultEntryEnvelope(v1)).toBe(false);
        expect(await decryptVaultEntry(v1, key, 'entry-1')).toEqual(data);
    });

    it('seals and opens a plaintext string in v2', async () => {
        const key = await freshKey();
        const sealed = await sealVaultEntryString('plain-text', key, 'entry-1');
        const opened = await openVaultEntryString(sealed, key, 'entry-1');
        expect(opened).toEqual({ plaintext: 'plain-text', version: 2 });
    });

    it('fails closed for unknown in-family versions', async () => {
        const key = await freshKey();
        await expect(
            decryptVaultEntry('sv-vault-v9:deadbeef', key, 'entry-1'),
        ).rejects.toBeInstanceOf(DisUnsupportedFormatVersionError);
    });

    it('rejects legacy no-AAD payloads on the runtime read path', async () => {
        const key = await freshKey();
        // A legacy payload: bare base64 AES-GCM with no AAD and no prefix.
        const legacy = await encryptString(JSON.stringify({ a: 1 }), key);
        await expect(decryptVaultEntry(legacy, key, 'entry-1')).rejects.toBeInstanceOf(
            DisLegacyPayloadError,
        );
    });

    it('reads legacy no-AAD payloads only on the migration path', async () => {
        const key = await freshKey();
        const legacy = await encryptString(JSON.stringify({ a: 1 }), key);
        const result = await decryptVaultEntryForMigration(legacy, key, 'entry-1');
        expect(result.data).toEqual({ a: 1 });
        expect(result.legacyEnvelopeUsed).toBe(true);
        expect(result.legacyNoAadFallbackUsed).toBe(true);
    });
});
