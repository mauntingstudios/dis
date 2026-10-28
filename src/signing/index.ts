/**
 * dis-signing — asymmetric digital signatures.
 *
 * Primitive: ECDSA over the NIST P-256 curve with SHA-256, via WebCrypto.
 * Public keys are exchanged as SPKI bytes; private keys are generated
 * non-extractable so they never leave the device. Signatures are the raw
 * `r || s` concatenation WebCrypto produces (fixed 64 bytes for P-256), which
 * is the exact wire form Singra Vault's op-log device signatures use.
 *
 * Canonicalisation of the signed payload is the caller's responsibility — DIS
 * signs and verifies opaque byte strings and never interprets their structure.
 */

import { subtle } from '../core/provider.js';
import { DisInvalidArgumentError } from '../core/errors.js';

const ECDSA_P256_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_P256_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** Order of the P-256 base point, and half of it for low-S normalisation. */
const P256_ORDER = BigInt(
    '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
);
const P256_HALF_ORDER = P256_ORDER / 2n;

/** Raw byte length of a P-256 ECDSA signature (`r || s`, 32 bytes each). */
export const ECDSA_P256_SIGNATURE_LENGTH = 64;

function bytesToBigInt(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
    }
    return value;
}

function bigIntToBytes32(value: bigint): Uint8Array {
    const out = new Uint8Array(32);
    let remaining = value;
    for (let i = 31; i >= 0; i -= 1) {
        out[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    return out;
}

export interface EcdsaP256KeyPair {
    readonly privateKey: CryptoKey;
    readonly publicKey: CryptoKey;
    /** SPKI-encoded public key bytes, ready to be base64url-encoded for storage. */
    readonly publicKeySpki: Uint8Array;
}

/**
 * Generates a fresh non-extractable ECDSA P-256 key pair and exports the
 * public key as SPKI bytes.
 */
export async function generateEcdsaP256KeyPair(): Promise<EcdsaP256KeyPair> {
    const keyPair = await subtle().generateKey(
        ECDSA_P256_ALGORITHM,
        /* extractable */ false,
        ['sign', 'verify'],
    );
    const spki = await subtle().exportKey('spki', keyPair.publicKey);
    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeySpki: new Uint8Array(spki),
    };
}

/** Imports an SPKI-encoded P-256 public key for signature verification. */
export async function importEcdsaP256PublicKeySpki(spki: Uint8Array): Promise<CryptoKey> {
    return subtle().importKey(
        'spki',
        spki as BufferSource,
        ECDSA_P256_ALGORITHM,
        false,
        ['verify'],
    );
}

/**
 * Signs `data` with an ECDSA P-256 private key, returning the raw 64-byte
 * `r || s` signature. The `s` value is normalised to the lower half of the
 * curve order, so a given message has one canonical signature rather than the
 * `(r, s)` / `(r, n-s)` pair. Verification still accepts high-S signatures so
 * existing stored signatures keep working.
 *
 * Throws {@link DisInvalidArgumentError} if WebCrypto returns an unexpected
 * length (defends against curve/algorithm misuse).
 */
export async function signEcdsaP256(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const signature = await subtle().sign(ECDSA_P256_PARAMS, privateKey, data as BufferSource);
    const bytes = new Uint8Array(signature);
    if (bytes.length !== ECDSA_P256_SIGNATURE_LENGTH) {
        throw new DisInvalidArgumentError('unexpected ECDSA signature byte length');
    }
    const s = bytesToBigInt(bytes.subarray(32));
    if (s > P256_HALF_ORDER) {
        bytes.set(bigIntToBytes32(P256_ORDER - s), 32);
    }
    return bytes;
}

/**
 * Verifies a raw 64-byte `r || s` ECDSA P-256 signature over `data`. Returns
 * `false` for an invalid signature; throws {@link DisInvalidArgumentError} if
 * the signature is not the expected length.
 */
export async function verifyEcdsaP256(
    publicKey: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
): Promise<boolean> {
    if (signature.length !== ECDSA_P256_SIGNATURE_LENGTH) {
        throw new DisInvalidArgumentError('unexpected ECDSA signature byte length');
    }
    try {
        return await subtle().verify(
            ECDSA_P256_PARAMS,
            publicKey,
            signature as BufferSource,
            data as BufferSource,
        );
    } catch {
        return false;
    }
}
