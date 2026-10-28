import { describe, expect, it } from 'vitest';
import {
    ECDSA_P256_SIGNATURE_LENGTH,
    generateEcdsaP256KeyPair,
    importEcdsaP256PublicKeySpki,
    signEcdsaP256,
    verifyEcdsaP256,
} from './index.js';
import { utf8ToBytes } from '../core/encoding.js';
import { DisInvalidArgumentError } from '../core/errors.js';

const P256_ORDER = BigInt(
    '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
);
const P256_HALF_ORDER = P256_ORDER / 2n;

function readS(signature: Uint8Array): bigint {
    let value = 0n;
    for (const byte of signature.subarray(32)) {
        value = (value << 8n) | BigInt(byte);
    }
    return value;
}

function writeS(value: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let remaining = value;
    for (let i = 31; i >= 0; i -= 1) {
        out[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return out;
}

describe('signing — ECDSA P-256', () => {
    it('produces a fixed 64-byte raw r||s signature that verifies', async () => {
        const { privateKey, publicKey } = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('vault-operation-canonical-body');
        const sig = await signEcdsaP256(privateKey, data);
        expect(sig.length).toBe(ECDSA_P256_SIGNATURE_LENGTH);
        expect(await verifyEcdsaP256(publicKey, sig, data)).toBe(true);
    });

    it('round-trips a public key through SPKI export/import', async () => {
        const { privateKey, publicKeySpki } = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('payload');
        const sig = await signEcdsaP256(privateKey, data);
        const imported = await importEcdsaP256PublicKeySpki(publicKeySpki);
        expect(await verifyEcdsaP256(imported, sig, data)).toBe(true);
    });

    it('rejects a tampered payload', async () => {
        const { privateKey, publicKey } = await generateEcdsaP256KeyPair();
        const sig = await signEcdsaP256(privateKey, utf8ToBytes('original'));
        expect(await verifyEcdsaP256(publicKey, sig, utf8ToBytes('tampered'))).toBe(false);
    });

    it('rejects a signature from a different key', async () => {
        const a = await generateEcdsaP256KeyPair();
        const b = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('payload');
        const sig = await signEcdsaP256(a.privateKey, data);
        expect(await verifyEcdsaP256(b.publicKey, sig, data)).toBe(false);
    });

    it('throws on a wrong-length signature', async () => {
        const { publicKey } = await generateEcdsaP256KeyPair();
        await expect(verifyEcdsaP256(publicKey, new Uint8Array(10), utf8ToBytes('x')))
            .rejects.toBeInstanceOf(DisInvalidArgumentError);
    });

    it('returns canonical low-S signatures', async () => {
        for (let i = 0; i < 24; i += 1) {
            const { privateKey } = await generateEcdsaP256KeyPair();
            const signature = await signEcdsaP256(privateKey, utf8ToBytes(`payload-${i}`));
            expect(readS(signature)).toBeLessThanOrEqual(P256_HALF_ORDER);
        }
    });

    it('still verifies a high-S alternate signature (compatibility)', async () => {
        const { privateKey, publicKey } = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('compatibility');
        const signature = await signEcdsaP256(privateKey, data);
        const alternate = new Uint8Array(64);
        alternate.set(signature.subarray(0, 32), 0);
        alternate.set(writeS(P256_ORDER - readS(signature)), 32);
        expect(await verifyEcdsaP256(publicKey, alternate, data)).toBe(true);
    });
});
