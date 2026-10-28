import { describe, expect, it } from 'vitest';
import { fillRandom, randomBytes, randomInt, randomUuid } from './index.js';
import { withFixedProvider } from '../test/disTestUtils.js';
import { DisInvalidArgumentError } from '../core/errors.js';

describe('random — randomInt', () => {
    it('always returns values within the inclusive range', () => {
        for (let i = 0; i < 2000; i++) {
            const v = randomInt(0, 30); // 31 = backup-code charset size
            expect(v).toBeGreaterThanOrEqual(0);
            expect(v).toBeLessThanOrEqual(30);
            expect(Number.isInteger(v)).toBe(true);
        }
    });

    it('returns the only value for a singleton range', () => {
        expect(randomInt(7, 7)).toBe(7);
    });

    it('covers the full range over many draws', () => {
        const seen = new Set<number>();
        for (let i = 0; i < 5000; i++) seen.add(randomInt(0, 9));
        for (let n = 0; n <= 9; n++) expect(seen.has(n)).toBe(true);
    });

    it('rejects invalid bounds', () => {
        expect(() => randomInt(5, 1)).toThrow(DisInvalidArgumentError);
        expect(() => randomInt(1.5, 3)).toThrow(DisInvalidArgumentError);
    });

    it('keeps the 32-bit accumulator unsigned at the top of the range', async () => {
        await withFixedProvider(new Uint8Array([0xff, 0xff, 0xff, 0xff]), async () => {
            expect(randomInt(0, 0xffffffff)).toBe(0xffffffff);
        });
        await withFixedProvider(new Uint8Array([0x80, 0x00, 0x00, 0x00]), async () => {
            expect(randomInt(0, 0xffffffff)).toBe(0x80000000);
        });
    });

    it('rejects ranges that do not fit into 32 bits', () => {
        expect(() => randomInt(0, 2 ** 40)).toThrow(DisInvalidArgumentError);
        expect(() => randomInt(0, 2 ** 32 + 1)).toThrow(DisInvalidArgumentError);
    });
});

describe('random — randomBytes / randomUuid', () => {
    it('rejects empty, negative and non-integer lengths', () => {
        expect(() => randomBytes(0)).toThrow(DisInvalidArgumentError);
        expect(() => randomBytes(-1)).toThrow(DisInvalidArgumentError);
        expect(() => randomBytes(1.5)).toThrow(DisInvalidArgumentError);
    });

    it('builds an RFC 4122 v4 UUID', () => {
        expect(randomUuid()).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        );
    });
});

describe('random — fillRandom', () => {
    it('fills the provided view in place', () => {
        const buf = new Uint8Array(32);
        const out = fillRandom(buf);
        expect(out).toBe(buf);
        expect(buf.some((b) => b !== 0)).toBe(true);
    });
});
