import { describe, expect, it } from 'vitest';
import {
    decryptAttachment,
    encryptAttachment,
    fileKeyAad,
    fileKeyAadV2,
    upgradeAttachmentManifest,
    type AttachmentContext,
    type FileManifest,
    type FileManifestV1,
    type FileManifestV2,
} from './index.js';
import { decryptBytes, encryptBytes } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import {
    DisDecryptionError,
    DisIntegrityError,
    DisInvalidArgumentError,
} from '../core/errors.js';

const ctx: AttachmentContext = { ownerId: 'owner-1', vaultItemId: 'item-1', fileId: 'file-1' };

interface Fixture {
    readonly vaultKey: CryptoKey;
    readonly plaintext: Uint8Array;
    readonly store: Map<number, string>;
    readonly manifest: FileManifestV2;
}

async function makeVaultKey(): Promise<CryptoKey> {
    return importAesGcmKey(randomBytes(32));
}

async function makeFixture(size = 9000, chunkSize = 4096): Promise<Fixture> {
    const vaultKey = await makeVaultKey();
    const plaintext = randomBytes(size);
    const store = new Map<number, string>();
    const { manifest } = await encryptAttachment({
        context: ctx,
        chunkSize,
        totalSize: plaintext.length,
        readChunk: async (start, end) => plaintext.slice(start, end),
        writeChunk: async (index, ciphertext) => {
            store.set(index, ciphertext);
            return ciphertext.length;
        },
        wrapFileKey: (bytes, aad) => encryptBytes(bytes, vaultKey, aad),
        metadata: {
            original_name: 'original.bin',
            mime_type: 'application/octet-stream',
            last_modified: 1,
        },
    });
    return { vaultKey, plaintext, store, manifest };
}

async function decryptFixture(
    fixture: Fixture,
    manifest: FileManifest = fixture.manifest,
    vaultKey: CryptoKey = fixture.vaultKey,
): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    await decryptAttachment({
        context: ctx,
        manifest,
        readChunk: async (index) => fixture.store.get(index)!,
        writeChunk: async (_index, chunk) => {
            chunks.push(new Uint8Array(chunk));
        },
        unwrapFileKey: (encrypted, aad) => decryptBytes(encrypted, vaultKey, aad),
    });
    const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out;
}

function toV1(manifest: FileManifestV2, vaultKey: CryptoKey): Promise<FileManifestV1> {
    return (async () => {
        const raw = await decryptBytes(manifest.wrapped_file_key, vaultKey, fileKeyAadV2(ctx));
        try {
            const wrapped = await encryptBytes(raw, vaultKey, fileKeyAad(ctx));
            const { manifest_mac: _mac, ...rest } = manifest;
            return { ...rest, version: 1, wrapped_file_key: wrapped };
        } finally {
            raw.fill(0);
        }
    })();
}

describe('file manifest v2 — format', () => {
    it('writes version 2 with a MAC and round-trips', async () => {
        const fixture = await makeFixture();
        expect(fixture.manifest.version).toBe(2);
        expect(fixture.manifest.manifest_mac.length).toBeGreaterThan(0);

        const out = await decryptFixture(fixture);
        expect(out).toEqual(fixture.plaintext);
    });

    it('does not cover wrapped_file_key in the MAC (password re-wrap keeps it valid)', async () => {
        const fixture = await makeFixture();
        const oldKey = fixture.vaultKey;
        const newKey = await makeVaultKey();

        const raw = await decryptBytes(fixture.manifest.wrapped_file_key, oldKey, fileKeyAadV2(ctx));
        let rewrapped: string;
        try {
            rewrapped = await encryptBytes(raw, newKey, fileKeyAadV2(ctx));
        } finally {
            raw.fill(0);
        }

        const rotated: FileManifestV2 = {
            ...fixture.manifest,
            wrapped_file_key: rewrapped,
        };
        expect(rotated.manifest_mac).toBe(fixture.manifest.manifest_mac);
        const out = await decryptFixture(fixture, rotated, newKey);
        expect(out).toEqual(fixture.plaintext);
    });
});

describe('file manifest v2 — negative', () => {
    it('rejects a dropped chunk when chunk_count still claims the original count', async () => {
        const fixture = await makeFixture();
        const tampered = structuredClone(fixture.manifest) as FileManifestV2;
        (tampered as { chunks: unknown }).chunks = tampered.chunks.slice(0, -1);
        await expect(decryptFixture(fixture, tampered)).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );
    });

    it('rejects a truncated chunk list with an adjusted chunk_count (MAC)', async () => {
        const fixture = await makeFixture();
        const tampered = structuredClone(fixture.manifest) as FileManifestV2;
        const chunks = tampered.chunks.slice(0, -1);
        (tampered as { chunks: unknown }).chunks = chunks;
        (tampered as { chunk_count: number }).chunk_count = chunks.length;
        await expect(decryptFixture(fixture, tampered)).rejects.toBeInstanceOf(DisIntegrityError);
    });

    it('rejects reordered, duplicated or gapped chunk indices', async () => {
        const fixture = await makeFixture();
        const variants: Array<(manifest: FileManifestV2) => void> = [
            (manifest) => {
                (manifest as { chunks: unknown }).chunks = [...manifest.chunks].reverse();
            },
            (manifest) => {
                const chunks = [...manifest.chunks];
                chunks[1] = { ...chunks[1]!, index: 0 };
                (manifest as { chunks: unknown }).chunks = chunks;
            },
            (manifest) => {
                const chunks = [...manifest.chunks];
                chunks[1] = { ...chunks[1]!, index: 5 };
                (manifest as { chunks: unknown }).chunks = chunks;
            },
        ];
        for (const mutate of variants) {
            const tampered = structuredClone(fixture.manifest) as FileManifestV2;
            mutate(tampered);
            await expect(decryptFixture(fixture, tampered)).rejects.toBeInstanceOf(
                DisInvalidArgumentError,
            );
        }
    });

    const fieldTampers: Array<[string, (manifest: FileManifestV2) => void]> = [
        ['original_name', (m) => ((m as { original_name: string }).original_name = 'renamed.txt')],
        ['mime_type', (m) => ((m as { mime_type: string }).mime_type = 'text/plain')],
        ['original_size', (m) => ((m as { original_size: number }).original_size += 1)],
        ['last_modified', (m) => ((m as { last_modified: number }).last_modified = 2)],
        ['uploaded_at', (m) => ((m as { uploaded_at: string }).uploaded_at = '2020-01-01T00:00:00.000Z')],
        ['chunk_size', (m) => ((m as { chunk_size: number }).chunk_size = 2048)],
        ['manifest_root', (m) => ((m as { manifest_root: string }).manifest_root = 'AAAA')],
        [
            'chunks[0].ciphertext_sha256',
            (m) =>
                ((m.chunks[0] as { ciphertext_sha256: string }).ciphertext_sha256 = 'AAAA'),
        ],
        [
            'chunks[0].ciphertext_size',
            (m) => ((m.chunks[0] as { ciphertext_size: number }).ciphertext_size += 1),
        ],
    ];

    it.each(fieldTampers)('rejects a tampered %s (MAC)', async (_field, mutate) => {
        const fixture = await makeFixture();
        const tampered = structuredClone(fixture.manifest) as FileManifestV2;
        mutate(tampered);
        await expect(decryptFixture(fixture, tampered)).rejects.toBeInstanceOf(DisIntegrityError);
    });

    it('rejects a missing or wrong MAC', async () => {
        const fixture = await makeFixture();

        const missing = structuredClone(fixture.manifest) as FileManifestV2;
        (missing as { manifest_mac: string }).manifest_mac = '';
        await expect(decryptFixture(fixture, missing)).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );

        const wrong = structuredClone(fixture.manifest) as FileManifestV2;
        (wrong as { manifest_mac: string }).manifest_mac = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
        await expect(decryptFixture(fixture, wrong)).rejects.toBeInstanceOf(DisIntegrityError);
    });

    it('rejects a v2 manifest downgraded to version 1 (key AAD binds the version)', async () => {
        const fixture = await makeFixture();
        const downgraded = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
        downgraded.version = 1;
        delete downgraded.manifest_mac;
        await expect(decryptFixture(fixture, downgraded as unknown as FileManifest)).rejects.toBeInstanceOf(
            DisDecryptionError,
        );
    });

    it('rejects a manifest from another attachment context', async () => {
        const fixture = await makeFixture();
        const wrongContext: AttachmentContext = { ...ctx, fileId: 'file-2' };
        await expect(
            decryptAttachment({
                context: wrongContext,
                manifest: fixture.manifest,
                readChunk: async (index) => fixture.store.get(index)!,
                writeChunk: async () => {},
                unwrapFileKey: (encrypted, aad) =>
                    decryptBytes(encrypted, fixture.vaultKey, aad),
            }),
        ).rejects.toBeInstanceOf(DisDecryptionError);
    });
});

describe('file manifest v1 — compatibility and upgrade', () => {
    it('reads a v1 manifest and reports its version', async () => {
        const fixture = await makeFixture();
        const v1 = await toV1(fixture.manifest, fixture.vaultKey);
        const out = await decryptFixture(fixture, v1);
        expect(out).toEqual(fixture.plaintext);
    });

    it('upgrades v1 to v2 by re-wrapping the same file key, then decrypts', async () => {
        const fixture = await makeFixture();
        const v1 = await toV1(fixture.manifest, fixture.vaultKey);
        const upgraded = await upgradeAttachmentManifest({
            context: ctx,
            manifest: v1,
            unwrapFileKey: (encrypted, aad) =>
                decryptBytes(encrypted, fixture.vaultKey, aad),
            wrapFileKey: (bytes, aad) => encryptBytes(bytes, fixture.vaultKey, aad),
        });

        expect(upgraded.version).toBe(2);
        expect(upgraded.wrapped_file_key).not.toBe(v1.wrapped_file_key);
        expect(upgraded.manifest_root).toBe(v1.manifest_root);
        expect(upgraded.chunks).toEqual(v1.chunks);

        const out = await decryptFixture(fixture, upgraded);
        expect(out).toEqual(fixture.plaintext);
    });

    it('refuses to upgrade a v1 manifest whose chunk list was truncated', async () => {
        const fixture = await makeFixture();
        const v1 = await toV1(fixture.manifest, fixture.vaultKey);
        const tampered = structuredClone(v1) as FileManifestV1;
        const chunks = tampered.chunks.slice(0, -1);
        (tampered as { chunks: unknown }).chunks = chunks;
        (tampered as { chunk_count: number }).chunk_count = chunks.length;

        await expect(
            upgradeAttachmentManifest({
                context: ctx,
                manifest: tampered,
                unwrapFileKey: (encrypted, aad) =>
                    decryptBytes(encrypted, fixture.vaultKey, aad),
                wrapFileKey: (bytes, aad) => encryptBytes(bytes, fixture.vaultKey, aad),
            }),
        ).rejects.toBeInstanceOf(DisIntegrityError);
    });
});
