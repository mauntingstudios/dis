import { describe, expect, it } from 'vitest';
import { MigrationRegistry, type Migration, type MigrationContext } from './index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import { DisError, DisInvalidArgumentError } from '../core/errors.js';

async function context(): Promise<MigrationContext> {
    return { key: await importAesGcmKey(randomBytes(32)), bindingId: 'entry-1' };
}

function step(
    fromVersion: number | 'legacy',
    toVersion: number,
    migrate: Migration['migrate'],
    subject = 'payload',
): Migration {
    return { subject, fromVersion, toVersion, migrate };
}

describe('migrations — negative', () => {
    it('rejects a duplicate migration for the same subject and version', () => {
        const registry = new MigrationRegistry();
        registry.register(step(1, 2, async (value) => value));
        expect(() => registry.register(step(1, 3, async (value) => value))).toThrow(
            DisInvalidArgumentError,
        );
    });

    it('stops a migration cycle instead of looping forever', async () => {
        const registry = new MigrationRegistry()
            .register(step(1, 2, async (value) => `${value}!`))
            .register(step(2, 1, async (value) => value.slice(0, -1)));
        const detect = (value: string): 1 | 2 => (value.endsWith('!') ? 2 : 1);

        await expect(
            registry.migrateToLatest('payload', 'seed', detect, await context()),
        ).rejects.toBeInstanceOf(DisError);
    });

    it('returns the payload unchanged when no migration matches', async () => {
        const registry = new MigrationRegistry();
        const result = await registry.migrateToLatest(
            'payload',
            'untouched',
            () => 1,
            await context(),
        );
        expect(result).toBe('untouched');
    });
});

describe('migrations — ordering', () => {
    it('runs each step once and in sequence', async () => {
        const calls: string[] = [];
        const registry = new MigrationRegistry()
            .register(
                step(1, 2, async (value) => {
                    calls.push('1->2');
                    return `${value}a`;
                }),
            )
            .register(
                step(2, 3, async (value) => {
                    calls.push('2->3');
                    return `${value}b`;
                }),
            );
        const detect = (value: string): number => {
            if (value.endsWith('ab')) return 3;
            if (value.endsWith('a')) return 2;
            return 1;
        };

        const result = await registry.migrateToLatest('payload', 'x', detect, await context());
        expect(result).toBe('xab');
        expect(calls).toEqual(['1->2', '2->3']);
    });
});
