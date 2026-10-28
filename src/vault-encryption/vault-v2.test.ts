import { describe, expect, it } from 'vitest';
import {
    VAULT_ITEM_ENVELOPE_V1_PREFIX,
    VAULT_ITEM_ENVELOPE_V2_PREFIX,
    decryptVaultEntry,
    decryptVaultEntryForMigration,
    encryptVaultEntry,
    sealVaultEntryString,
    openVaultEntryString,
} from './index.js';
import { encryptString } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import {
    DisDecryptionError,
    DisInvalidArgumentError,
    DisLegacyPayloadError,
    DisUnsupportedFormatVersionError,
} from '../core/errors.js';

async function freshKey(): Promise<CryptoKey> {
    return importAesGcmKey(randomBytes(32));
}

async function v1Envelope(
    data: Record<string, unknown>,
    key: CryptoKey,
    entryId: string,
): Promise<string> {
    const payload = await encryptString(JSON.stringify(data), key, entryId);
    return `${VAULT_ITEM_ENVELOPE_V1_PREFIX}${payload}`;
}

describe('vault v2 — negative', () => {
    it('rejects a v2 payload whose prefix was stripped (no legacy downgrade)', async () => {
        const key = await freshKey();
        const sealed = await encryptVaultEntry({ password: 'x' }, key, 'entry-1');
        const stripped = sealed.slice(VAULT_ITEM_ENVELOPE_V2_PREFIX.length);
        await expect(decryptVaultEntry(stripped, key, 'entry-1')).rejects.toBeInstanceOf(
            DisLegacyPayloadError,
        );
    });

    it('still reads a v1 payload whose prefix was stripped (documented compatibility)', async () => {
        const key = await freshKey();
        const data = { password: 'legacy' };
        const v1 = await v1Envelope(data, key, 'entry-1');
        const stripped = v1.slice(VAULT_ITEM_ENVELOPE_V1_PREFIX.length);
        expect(await decryptVaultEntry(stripped, key, 'entry-1')).toEqual(data);
    });

    it('rejects a v2 payload relabeled as v1', async () => {
        const key = await freshKey();
        const sealed = await encryptVaultEntry({ password: 'x' }, key, 'entry-1');
        const relabeled = `${VAULT_ITEM_ENVELOPE_V1_PREFIX}${sealed.slice(
            VAULT_ITEM_ENVELOPE_V2_PREFIX.length,
        )}`;
        await expect(decryptVaultEntry(relabeled, key, 'entry-1')).rejects.toBeInstanceOf(
            DisDecryptionError,
        );
    });

    it('rejects a v1 payload relabeled as v2', async () => {
        const key = await freshKey();
        const v1 = await v1Envelope({ password: 'legacy' }, key, 'entry-1');
        const relabeled = `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${v1.slice(
            VAULT_ITEM_ENVELOPE_V1_PREFIX.length,
        )}`;
        await expect(decryptVaultEntry(relabeled, key, 'entry-1')).rejects.toBeInstanceOf(
            DisDecryptionError,
        );
    });

    it('rejects a v2 entry under a different entryId', async () => {
        const key = await freshKey();
        const sealed = await encryptVaultEntry({ password: 'x' }, key, 'entry-1');
        await expect(decryptVaultEntry(sealed, key, 'entry-2')).rejects.toBeInstanceOf(
            DisDecryptionError,
        );
    });

    it('rejects unknown in-family versions', async () => {
        const key = await freshKey();
        await expect(decryptVaultEntry('sv-vault-v3:deadbeef', key, 'entry-1')).rejects.toBeInstanceOf(
            DisUnsupportedFormatVersionError,
        );
    });

    it('rejects empty entry ids and empty payloads', async () => {
        const key = await freshKey();
        const sealed = await encryptVaultEntry({ password: 'x' }, key, 'entry-1');
        await expect(decryptVaultEntry(sealed, key, '')).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );
        await expect(sealVaultEntryString('x', key, '')).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );
        await expect(decryptVaultEntry(VAULT_ITEM_ENVELOPE_V2_PREFIX, key, 'entry-1')).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );
    });

    it('reports v2 and v1 correctly on the migration path', async () => {
        const key = await freshKey();
        const v2 = await encryptVaultEntry({ password: 'x' }, key, 'entry-1');
        const v2Result = await decryptVaultEntryForMigration(v2, key, 'entry-1');
        expect(v2Result.legacyEnvelopeUsed).toBe(false);
        expect(v2Result.legacyNoAadFallbackUsed).toBe(false);

        const v1 = await v1Envelope({ password: 'legacy' }, key, 'entry-1');
        const v1Result = await decryptVaultEntryForMigration(v1, key, 'entry-1');
        expect(v1Result.legacyEnvelopeUsed).toBe(true);
        expect(v1Result.legacyNoAadFallbackUsed).toBe(false);
    });

    it('rejects legacy no-AAD on the runtime path but reads it on migration', async () => {
        const key = await freshKey();
        const legacy = await encryptString(JSON.stringify({ password: 'old' }), key);
        await expect(decryptVaultEntry(legacy, key, 'entry-1')).rejects.toBeInstanceOf(
            DisLegacyPayloadError,
        );
        const migrated = await decryptVaultEntryForMigration(legacy, key, 'entry-1');
        expect(migrated.data).toEqual({ password: 'old' });
        expect(migrated.legacyNoAadFallbackUsed).toBe(true);
    });

    it('opens a v1 string payload through the string seam', async () => {
        const key = await freshKey();
        const v1 = await v1Envelope({ password: 'legacy' }, key, 'entry-1');
        const opened = await openVaultEntryString(v1, key, 'entry-1');
        expect(opened.version).toBe(1);
        expect(JSON.parse(opened.plaintext)).toEqual({ password: 'legacy' });
    });
});
