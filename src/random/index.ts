/**
 * dis-random — secure random generation.
 *
 * Always sources entropy from the active crypto provider's CSPRNG
 * (`getRandomValues`). DIS never uses `Math.random` for any value that affects
 * confidentiality, integrity, or unpredictability.
 */

import { getCryptoProvider } from '../core/provider.js';
import { DisInvalidArgumentError } from '../core/errors.js';

/** Returns `length` cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
    if (!Number.isInteger(length) || length <= 0) {
        throw new DisInvalidArgumentError('randomBytes length must be a positive integer');
    }
    const out = new Uint8Array(length);
    getCryptoProvider().getRandomValues(out);
    return out;
}

/**
 * Fills an existing `ArrayBufferView` with cryptographically secure random
 * bytes in place. Used by callers that own a buffer they want to overwrite
 * (e.g. secure-memory scrubbing) without allocating a second array.
 */
export function fillRandom<T extends ArrayBufferView>(view: T): T {
    return getCryptoProvider().getRandomValues(view);
}

/**
 * Returns a cryptographically secure random integer in the inclusive range
 * `[min, max]` using rejection sampling to avoid modulo bias.
 *
 * Byte-for-byte equivalent to the `getSecureRandomInt` helpers in Singra Vault
 * (password generator, backup-code generator): it draws `ceil(log2(range)/8)`
 * bytes big-endian and rejects values above the largest multiple of `range`.
 *
 * The range is capped at 2^32 values. Larger ranges would need more than four
 * random bytes; the 32-bit accumulator below would silently wrap. Callers that
 * need a wider identifier should compose several draws instead.
 */
export function randomInt(min: number, max: number): number {
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
        throw new DisInvalidArgumentError('randomInt bounds must be integers');
    }
    if (max < min) {
        throw new DisInvalidArgumentError('randomInt max must be >= min');
    }
    const range = max - min + 1;
    if (!Number.isSafeInteger(range) || range > 0x1_0000_0000) {
        throw new DisInvalidArgumentError('randomInt range must be <= 2^32');
    }
    if (range === 1) {
        return min;
    }
    const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
    const maxValid = Math.floor((256 ** bytesNeeded) / range) * range - 1;
    const buffer = new Uint8Array(bytesNeeded);
    let randomValue: number;
    do {
        getCryptoProvider().getRandomValues(buffer);
        randomValue = 0;
        for (let i = 0; i < bytesNeeded; i++) {
            // `>>> 0` keeps the accumulator unsigned; plain `<<` wraps at 2^31.
            randomValue = ((randomValue << 8) | buffer[i]!) >>> 0;
        }
    } while (randomValue > maxValid);
    return min + (randomValue % range);
}

/** Returns a RFC 4122 v4 UUID using the provider's CSPRNG. */
export function randomUuid(): string {
    const provider = getCryptoProvider() as { randomUUID?: () => string };
    if (typeof provider.randomUUID === 'function') {
        return provider.randomUUID();
    }
    // Fallback: build a v4 UUID from random bytes.
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;
    const hex: string[] = [];
    for (let i = 0; i < 16; i++) hex.push(bytes[i]!.toString(16).padStart(2, '0'));
    return (
        `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-` +
        `${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`
    );
}
