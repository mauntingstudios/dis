import { describe, it, expect } from 'vitest';
import * as vault from './index.js';
import { DisDecryptionError, DisUnsupportedFormatVersionError } from '../core/errors.js';

describe('STRESS & HARDENING: Vault Cryptolayer Resiliency', () => {
    const PW = 'MasterPassword-VeryStrong-1234!';
    const SALT = 'c2FsdHktc2FsdC1zYWx0eQ=='; // 16 bytes base64

    it('Scenario 3A: Corrupted Envelopes (Byte-Flipping Fuzzing) must always fail closed', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);
        const entryId = 'item-stress-1';
        const originalData = { password: 'TopSecretCredentials-2026', username: 'admin' };

        const sealed = await vault.encryptVaultItem(originalData, bundle.userKey, entryId);
        expect(sealed.startsWith('sv-vault-v2:')).toBe(true);

        const payloadPart = sealed.replace('sv-vault-v2:', '');

        // 1. Bit-flipping across multiple positions
        const flipPositions = [0, 5, 10, 20, payloadPart.length - 1, Math.floor(payloadPart.length / 2)];
        for (const pos of flipPositions) {
            const rawChars = payloadPart.split('');
            const currentCharCode = rawChars[pos].charCodeAt(0);
            rawChars[pos] = String.fromCharCode(currentCharCode ^ 0x01);
            const corruptedEnvelope = `sv-vault-v1:${rawChars.join('')}`;

            await expect(
                vault.decryptVaultItem(corruptedEnvelope, bundle.userKey, entryId),
            ).rejects.toThrow();
        }

        // 2. Truncated Envelopes
        const truncatedEnvelope = sealed.substring(0, sealed.length - 16);
        await expect(
            vault.decryptVaultItem(truncatedEnvelope, bundle.userKey, entryId),
        ).rejects.toThrow();

        // 3. Rubbish / Non-base64 payload
        const garbageEnvelope = 'sv-vault-v1:!@#$%^&*()_+=-INVALID-BYTES==';
        await expect(
            vault.decryptVaultItem(garbageEnvelope, bundle.userKey, entryId),
        ).rejects.toThrow();

        kdfOut.fill(0);
    });

    it('Scenario 3B: Unknown / Malicious Version Envelopes must reject with DisUnsupportedFormatVersionError', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);
        const entryId = 'item-stress-2';

        const fakeVersions = [
            'sv-vault-v0:somevalidpayload',
            'sv-vault-v3:futureversionpayload',
            'sv-vault-v999:attackerpayload',
            'sv-vault-vbeta:test',
        ];

        for (const fakeEnv of fakeVersions) {
            await expect(
                vault.decryptVaultItem(fakeEnv, bundle.userKey, entryId),
            ).rejects.toThrow(DisUnsupportedFormatVersionError);
        }

        kdfOut.fill(0);
    });

    it('Scenario 3C: AAD Context-Swap Attacks must strictly fail closed', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);
        const originalData = { password: 'SensitiveBankPassword' };

        const sealedItemA = await vault.encryptVaultItem(originalData, bundle.userKey, 'entry-item-A');

        // Attacker attempts to decrypt item A payload under item B entryId
        await expect(
            vault.decryptVaultItem(sealedItemA, bundle.userKey, 'entry-item-B'),
        ).rejects.toThrow();

        // Attacker attempts to pass empty entryId or path-traversal entryId
        await expect(
            vault.decryptVaultItem(sealedItemA, bundle.userKey, ''),
        ).rejects.toThrow();
        await expect(
            vault.decryptVaultItem(sealedItemA, bundle.userKey, '../../etc/passwd'),
        ).rejects.toThrow();

        kdfOut.fill(0);
    });

    it('Scenario 3D: UserKey Wrap Corruption & Wrong KDF Key', async () => {
        const kdfOut = await vault.deriveRawKey(PW, SALT, 2);
        const bundle = await vault.createEncryptedUserKey(kdfOut);

        // Wrong password / wrong KDF
        const wrongKdf = await vault.deriveRawKey('WrongMasterPassword!', SALT, 2);
        await expect(
            vault.unwrapUserKey(bundle.encryptedUserKey, wrongKdf),
        ).rejects.toThrow();

        // Corrupted USK bundle
        const corruptedUsk = bundle.encryptedUserKey.replace('usk-wrap-v2:', 'usk-wrap-v2:corrupted');
        await expect(
            vault.unwrapUserKey(corruptedUsk, kdfOut),
        ).rejects.toThrow();

        kdfOut.fill(0);
        wrongKdf.fill(0);
    });
});
