/**
 * dis-file-encryption / dis-attachment-streams — chunked file & attachment
 * encryption.
 *
 * Model (byte-compatible with Singra Premium):
 *   - A fresh random per-file AES-256 key encrypts the file content.
 *   - The file is split into fixed-size chunks; each chunk is sealed with
 *     AES-256-GCM and a per-chunk AAD binding it to owner/item/file/revision/
 *     manifest-root/index/count (defeats reorder, splice and cross-file swap).
 *   - The file key is wrapped by an outer vault key (supplied as a callback),
 *     bound by a file-key AAD.
 *   - A manifest records chunk hashes and a manifest root. Version 2 is
 *     authenticated with an HMAC over every manifest field (metadata, chunk
 *     layout, hashes). The manifest is **not** encrypted: names, MIME types and
 *     sizes stay visible wherever the manifest is stored. Version 1 manifests
 *     are legacy: they carry no MAC and are only read for compatibility.
 *
 * DIS owns the cryptography and the format. It is storage-agnostic: callers
 * supply chunk read/write callbacks, so transport (e.g. object storage, local
 * FS) stays in the application.
 */

import { decryptBytes, encryptBytes } from '../aead/index.js';
import { deriveHkdfSha256Bits, importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import {
    constantTimeEqualBase64,
    hmacSha256,
    sha256Base64,
    sha256JsonBase64,
} from '../integrity/index.js';
import { bytesToBase64, concatBytes, utf8ToBytes } from '../core/encoding.js';
import { AES_KEY_LENGTH } from '../core/constants.js';
import { DisIntegrityError, DisInvalidArgumentError } from '../core/errors.js';

/** Default chunk size (4 MiB), matching the Singra Premium format. */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

/** Legacy manifest prefix. Manifests are objects with a `version` field, not wrapped strings. */
export const FILE_MANIFEST_V1_PREFIX = 'sv-file-manifest-v1:';

/** Opaque binding context for an attachment. Ids are treated as opaque strings. */
export interface AttachmentContext {
    readonly ownerId: string;
    readonly vaultItemId: string;
    readonly fileId: string;
}

/** Encrypts text with the outer vault key (e.g. DIS aead.encryptString). */
export type VaultEncryptText = (plaintext: string, aad?: string) => Promise<string>;
export type VaultDecryptText = (encrypted: string, aad?: string) => Promise<string>;
export type VaultEncryptBytes = (plaintext: Uint8Array, aad?: string) => Promise<string>;
export type VaultDecryptBytes = (encrypted: string, aad?: string) => Promise<Uint8Array>;

export interface FileChunkManifest {
    readonly index: number;
    readonly plaintext_size: number;
    readonly ciphertext_size: number;
    readonly ciphertext_sha256: string;
}

export interface FileManifestV1 {
    readonly version: 1;
    readonly algorithm: 'AES-256-GCM';
    readonly file_id: string;
    readonly file_revision: number;
    readonly previous_manifest_hash: string | null;
    readonly manifest_root: string;
    readonly owner_id: string;
    readonly vault_item_id: string;
    readonly original_name: string;
    readonly mime_type: string | null;
    readonly original_size: number;
    readonly last_modified: number | null;
    readonly uploaded_at: string;
    readonly chunk_size: number;
    readonly chunk_count: number;
    readonly wrapped_file_key: string;
    readonly chunks: readonly FileChunkManifest[];
    readonly preview: null;
    readonly notes: null;
}

/**
 * Authenticated manifest. `manifest_mac` is an HMAC-SHA-256 over a canonical
 * field list; see {@link computeManifestMac}. It deliberately does **not** cover
 * `wrapped_file_key`, because that field is re-wrapped on a password change
 * while the file key (and therefore the MAC key) stays the same.
 *
 * The manifest version is bound through {@link fileKeyAadV2}: a v2 manifest
 * whose `wrapped_file_key` is unwrapped with the v1 AAD fails, so downgrading
 * the manifest version is not a way around the MAC.
 */
export interface FileManifestV2 extends Omit<FileManifestV1, 'version'> {
    readonly version: 2;
    readonly manifest_mac: string;
}

export type FileManifest = FileManifestV1 | FileManifestV2;

// ---- Canonical AAD / MAC context (format contract) ------------------------

/**
 * @deprecated The v2 manifest authenticates through {@link manifestMacContext}.
 * Kept for compatibility with callers that used the v1 domain string.
 */
export function manifestAad(ctx: AttachmentContext): string {
    return `sv-file-manifest-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

/** Domain-separated HMAC context for the v2 manifest. */
export function manifestMacContext(ctx: AttachmentContext): string {
    return `sv-file-manifest-mac-v2:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

/** v1 file-key AAD. Kept for reading legacy manifests. */
export function fileKeyAad(ctx: AttachmentContext): string {
    return `sv-file-key-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

/** v2 file-key AAD. Binds the manifest version to the wrapped file key. */
export function fileKeyAadV2(ctx: AttachmentContext): string {
    return `sv-file-key-v2:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

export function chunkAad(
    ctx: AttachmentContext,
    fileRevision: number,
    manifestRoot: string,
    chunkIndex: number,
    chunkCount: number,
): string {
    return (
        `sv-file-chunk-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}:` +
        `${fileRevision}:${manifestRoot}:${chunkIndex}:${chunkCount}`
    );
}

// ---- Manifest authentication ----------------------------------------------

const MANIFEST_MAC_DOMAIN = 'sv-file-manifest-v2';
const MANIFEST_MAC_INFO_PREFIX = 'sv-file-manifest-mac-v2:';
const AAD_SEPARATOR = new Uint8Array([0x00]);

/**
 * Explicit, ordered field list. Do not replace this with
 * `JSON.stringify(manifest)`: property order and newly added fields would then
 * silently change the MAC input.
 */
function canonicalManifestBytes(
    manifest: FileManifest | Omit<FileManifestV2, 'manifest_mac'>,
): Uint8Array {
    const fields: unknown[] = [
        manifest.version,
        manifest.algorithm,
        manifest.file_id,
        manifest.file_revision,
        manifest.previous_manifest_hash,
        manifest.manifest_root,
        manifest.owner_id,
        manifest.vault_item_id,
        manifest.original_name,
        manifest.mime_type,
        manifest.original_size,
        manifest.last_modified,
        manifest.uploaded_at,
        manifest.chunk_size,
        manifest.chunk_count,
        manifest.chunks.map((chunk) => [
            chunk.index,
            chunk.plaintext_size,
            chunk.ciphertext_size,
            chunk.ciphertext_sha256,
        ]),
        manifest.preview,
        manifest.notes,
    ];
    return utf8ToBytes(JSON.stringify(fields));
}

async function deriveManifestMacKey(
    fileKeyBytes: Uint8Array,
    ctx: AttachmentContext,
): Promise<Uint8Array> {
    return deriveHkdfSha256Bits(fileKeyBytes, {
        info: utf8ToBytes(`${MANIFEST_MAC_INFO_PREFIX}${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`),
        lengthBits: 256,
    });
}

async function computeManifestMac(
    fileKeyBytes: Uint8Array,
    ctx: AttachmentContext,
    manifest: FileManifest | Omit<FileManifestV2, 'manifest_mac'>,
): Promise<string> {
    const macKey = await deriveManifestMacKey(fileKeyBytes, ctx);
    try {
        const payload = concatBytes(
            utf8ToBytes(MANIFEST_MAC_DOMAIN),
            AAD_SEPARATOR,
            utf8ToBytes(manifestMacContext(ctx)),
            AAD_SEPARATOR,
            canonicalManifestBytes(manifest),
        );
        try {
            return bytesToBase64(await hmacSha256(macKey, payload));
        } finally {
            payload.fill(0);
        }
    } finally {
        macKey.fill(0);
    }
}

async function verifyManifestMac(
    fileKeyBytes: Uint8Array,
    ctx: AttachmentContext,
    manifest: FileManifestV2,
): Promise<void> {
    const expected = await computeManifestMac(fileKeyBytes, ctx, manifest);
    let matches = false;
    try {
        matches = constantTimeEqualBase64(expected, manifest.manifest_mac);
    } catch {
        matches = false;
    }
    if (!matches) {
        throw new DisIntegrityError('File manifest authentication failed');
    }
}

async function sealManifestV2(
    manifest: Omit<FileManifestV2, 'manifest_mac'>,
    fileKeyBytes: Uint8Array,
    ctx: AttachmentContext,
): Promise<FileManifestV2> {
    const manifestMac = await computeManifestMac(fileKeyBytes, ctx, manifest);
    return { ...manifest, manifest_mac: manifestMac };
}

// ---- Manifest validation ---------------------------------------------------

function requireString(value: unknown, field: string): string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new DisInvalidArgumentError(`${field} must be a non-empty string`);
    }
    return value;
}

function requireNonNegativeInt(value: unknown, field: string): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
        throw new DisInvalidArgumentError(`${field} must be a non-negative integer`);
    }
    return value;
}

function requirePositiveInt(value: unknown, field: string): number {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
        throw new DisInvalidArgumentError(`${field} must be a positive integer`);
    }
    return value;
}

/**
 * Structural validation only. It does not prove authenticity; that is the MAC
 * (v2) or the caller's explicit legacy decision (v1).
 */
function validateManifestStructure(manifest: FileManifest): void {
    if (!manifest || typeof manifest !== 'object') {
        throw new DisInvalidArgumentError('File manifest must be an object');
    }
    if (manifest.version !== 1 && manifest.version !== 2) {
        throw new DisInvalidArgumentError('Unsupported file manifest version');
    }
    if (manifest.algorithm !== 'AES-256-GCM') {
        throw new DisInvalidArgumentError('Unsupported file manifest algorithm');
    }
    requireString(manifest.file_id, 'file_id');
    requireString(manifest.manifest_root, 'manifest_root');
    requireString(manifest.owner_id, 'owner_id');
    requireString(manifest.vault_item_id, 'vault_item_id');
    requireString(manifest.original_name, 'original_name');
    requireString(manifest.uploaded_at, 'uploaded_at');
    requireString(manifest.wrapped_file_key, 'wrapped_file_key');
    if (manifest.mime_type !== null && typeof manifest.mime_type !== 'string') {
        throw new DisInvalidArgumentError('mime_type must be a string or null');
    }
    if (manifest.previous_manifest_hash !== null && typeof manifest.previous_manifest_hash !== 'string') {
        throw new DisInvalidArgumentError('previous_manifest_hash must be a string or null');
    }
    if (manifest.last_modified !== null) {
        requireNonNegativeInt(manifest.last_modified, 'last_modified');
    }
    requireNonNegativeInt(manifest.file_revision, 'file_revision');
    requireNonNegativeInt(manifest.original_size, 'original_size');
    requirePositiveInt(manifest.chunk_size, 'chunk_size');
    requirePositiveInt(manifest.chunk_count, 'chunk_count');
    if (!Array.isArray(manifest.chunks)) {
        throw new DisInvalidArgumentError('chunks must be an array');
    }
    if (manifest.chunks.length !== manifest.chunk_count) {
        throw new DisInvalidArgumentError('chunk_count does not match the chunk list');
    }
    for (let index = 0; index < manifest.chunks.length; index += 1) {
        const chunk = manifest.chunks[index];
        if (!chunk || typeof chunk !== 'object' || chunk.index !== index) {
            throw new DisInvalidArgumentError(`chunks[${index}] is malformed or out of order`);
        }
        requireNonNegativeInt(chunk.plaintext_size, `chunks[${index}].plaintext_size`);
        requireNonNegativeInt(chunk.ciphertext_size, `chunks[${index}].ciphertext_size`);
        requireString(chunk.ciphertext_sha256, `chunks[${index}].ciphertext_sha256`);
    }
    if (manifest.version === 2) {
        requireString(manifest.manifest_mac, 'manifest_mac');
    }
}

/**
 * Consistency checks that do not depend on authenticity: sizes, indices and the
 * manifest root. They run after the MAC for v2 and before any chunk I/O for v1,
 * so a truncated legacy manifest is never mistaken for a valid file.
 */
async function validateManifestConsistency(manifest: FileManifest): Promise<void> {
    const originalSize = manifest.chunks.reduce(
        (total, chunk) => total + chunk.plaintext_size,
        0,
    );
    if (originalSize !== manifest.original_size) {
        throw new DisIntegrityError('File manifest size does not match the chunk list');
    }
    const expectedCount = Math.max(1, Math.ceil(manifest.original_size / manifest.chunk_size));
    if (manifest.chunk_count !== expectedCount) {
        throw new DisIntegrityError('File manifest chunk count does not match its size');
    }
    const expectedRoot = await computeManifestRoot({
        fileId: manifest.file_id,
        fileRevision: manifest.file_revision,
        chunkSize: manifest.chunk_size,
        chunkCount: manifest.chunk_count,
        chunks: manifest.chunks.map((chunk) => ({
            index: chunk.index,
            plaintext_size: chunk.plaintext_size,
        })),
    });
    if (!constantTimeEqualBase64(expectedRoot, manifest.manifest_root)) {
        throw new DisIntegrityError('File manifest root does not match the chunk list');
    }
}

// ---- File-key handling ----------------------------------------------------

/** Generates fresh per-file AES-256 key bytes (caller must wipe). */
export function generateFileKeyBytes(): Uint8Array {
    return randomBytes(AES_KEY_LENGTH);
}

/** Imports raw file-key bytes as a non-extractable AES-GCM key. */
export function importFileKey(rawKey: Uint8Array): Promise<CryptoKey> {
    return importAesGcmKey(rawKey);
}

// ---- Chunk crypto ---------------------------------------------------------

/** Seals one plaintext chunk. `plaintext` is wiped before returning. */
export async function encryptChunk(
    plaintext: Uint8Array,
    fileKey: CryptoKey,
    aad: string,
): Promise<string> {
    try {
        return await encryptBytes(plaintext, fileKey, aad);
    } finally {
        plaintext.fill(0);
    }
}

/** Opens one chunk. Returned bytes are plaintext — caller must wipe. */
export async function decryptChunk(
    encryptedBase64: string,
    fileKey: CryptoKey,
    aad: string,
): Promise<Uint8Array> {
    return decryptBytes(encryptedBase64, fileKey, aad);
}

// ---- Manifest helpers -----------------------------------------------------

interface PlannedChunk {
    readonly index: number;
    readonly plaintext_size: number;
}

/**
 * Computes the manifest root: a SHA-256 over the planned chunk layout. Binding
 * each chunk's AAD to this root prevents chunk-count / size tampering.
 */
export async function computeManifestRoot(input: {
    fileId: string;
    fileRevision: number;
    chunkSize: number;
    chunkCount: number;
    chunks: readonly PlannedChunk[];
}): Promise<string> {
    return sha256JsonBase64({
        file_id: input.fileId,
        file_revision: input.fileRevision,
        chunk_size: input.chunkSize,
        chunk_count: input.chunkCount,
        chunks: input.chunks.map((c) => ({
            index: c.index,
            storage_path: undefined,
            plaintext_size: c.plaintext_size,
        })),
    });
}

/** SHA-256 (base64) of a ciphertext chunk, for the manifest. */
export function chunkCiphertextHash(ciphertextBase64: string): Promise<string> {
    return sha256Base64(new TextEncoder().encode(ciphertextBase64));
}

export interface EncryptAttachmentInput {
    readonly context: AttachmentContext;
    readonly fileRevision?: number;
    readonly chunkSize?: number;
    /** Total plaintext size in bytes (used to plan chunks). */
    readonly totalSize: number;
    /** Returns the plaintext bytes for chunk `[start, end)`. */
    readonly readChunk: (start: number, end: number) => Promise<Uint8Array>;
    /** Persists a sealed chunk; returns its stored ciphertext size in bytes. */
    readonly writeChunk: (index: number, ciphertextBase64: string) => Promise<number>;
    /** Wraps the per-file key with the outer vault key. */
    readonly wrapFileKey: VaultEncryptBytes;
    readonly metadata: {
        readonly original_name: string;
        readonly mime_type: string | null;
        readonly last_modified: number | null;
    };
}

export interface EncryptAttachmentResult {
    readonly manifest: FileManifestV2;
    readonly manifestRoot: string;
}

/**
 * Encrypts an attachment chunk-by-chunk and produces an authenticated manifest.
 * Storage is delegated to `readChunk`/`writeChunk`. The returned manifest's
 * `wrapped_file_key` is bound to the file via {@link fileKeyAad}.
 */
export async function encryptAttachment(
    input: EncryptAttachmentInput,
): Promise<EncryptAttachmentResult> {
    const chunkSize = input.chunkSize ?? DEFAULT_CHUNK_SIZE;
    if (chunkSize <= 0) throw new DisInvalidArgumentError('chunkSize must be positive');
    const fileRevision = input.fileRevision ?? 1;
    const chunkCount = Math.max(1, Math.ceil(input.totalSize / chunkSize));
    const ctx = input.context;

    const plannedChunks: PlannedChunk[] = Array.from({ length: chunkCount }, (_, index) => {
        const start = index * chunkSize;
        const end = Math.min(input.totalSize, start + chunkSize);
        return { index, plaintext_size: end - start };
    });
    const manifestRoot = await computeManifestRoot({
        fileId: ctx.fileId,
        fileRevision,
        chunkSize,
        chunkCount,
        chunks: plannedChunks,
    });

    const fileKeyBytes = generateFileKeyBytes();
    const fileKey = await importFileKey(fileKeyBytes);
    const chunks: FileChunkManifest[] = [];
    try {
        const wrappedFileKey = await input.wrapFileKey(fileKeyBytes, fileKeyAadV2(ctx));
        for (let index = 0; index < chunkCount; index += 1) {
            const start = index * chunkSize;
            const end = Math.min(input.totalSize, start + chunkSize);
            const plaintext = await input.readChunk(start, end);
            const aad = chunkAad(ctx, fileRevision, manifestRoot, index, chunkCount);
            const ciphertext = await encryptChunk(plaintext, fileKey, aad);
            const ciphertextSize = await input.writeChunk(index, ciphertext);
            chunks.push({
                index,
                plaintext_size: plannedChunks[index]!.plaintext_size,
                ciphertext_size: ciphertextSize,
                ciphertext_sha256: await chunkCiphertextHash(ciphertext),
            });
        }

        const manifest = await sealManifestV2(
            {
                version: 2,
                algorithm: 'AES-256-GCM',
                file_id: ctx.fileId,
                file_revision: fileRevision,
                previous_manifest_hash: null,
                manifest_root: manifestRoot,
                owner_id: ctx.ownerId,
                vault_item_id: ctx.vaultItemId,
                original_name: input.metadata.original_name,
                mime_type: input.metadata.mime_type,
                original_size: input.totalSize,
                last_modified: input.metadata.last_modified,
                uploaded_at: new Date().toISOString(),
                chunk_size: chunkSize,
                chunk_count: chunkCount,
                wrapped_file_key: wrappedFileKey,
                chunks,
                preview: null,
                notes: null,
            },
            fileKeyBytes,
            ctx,
        );
        return { manifest, manifestRoot };
    } finally {
        fileKeyBytes.fill(0);
    }
}

export interface DecryptAttachmentInput {
    readonly context: AttachmentContext;
    readonly manifest: FileManifest;
    /** Reads a stored ciphertext chunk by index. */
    readonly readChunk: (index: number, storedSha256: string) => Promise<string>;
    /** Receives a decrypted plaintext chunk (caller may stream to disk). */
    readonly writeChunk: (index: number, plaintext: Uint8Array) => Promise<void>;
    /** Unwraps the per-file key using the outer vault key. */
    readonly unwrapFileKey: VaultDecryptBytes;
    /** If true (default), verify each chunk's stored ciphertext hash. */
    readonly verifyChunkHashes?: boolean;
}

export interface DecryptAttachmentResult {
    /** The version that was actually read. v1 is legacy and carries no MAC. */
    readonly manifestVersion: 1 | 2;
}

/**
 * Decrypts an attachment by streaming chunks through `readChunk`/`writeChunk`.
 *
 * v2 verifies the manifest MAC before any chunk I/O and checks the chunk list,
 * root and sizes. v1 is legacy: it is read for compatibility, but only after
 * the same structural checks, so a truncated v1 manifest fails instead of
 * silently yielding a prefix.
 */
export async function decryptAttachment(
    input: DecryptAttachmentInput,
): Promise<DecryptAttachmentResult> {
    const { manifest, context: ctx } = input;
    validateManifestStructure(manifest);
    const verifyHashes = input.verifyChunkHashes ?? true;

    const fileKeyBytes = await input.unwrapFileKey(
        manifest.wrapped_file_key,
        manifest.version === 2 ? fileKeyAadV2(ctx) : fileKeyAad(ctx),
    );
    try {
        if (manifest.version === 2) {
            await verifyManifestMac(fileKeyBytes, ctx, manifest);
        }
        await validateManifestConsistency(manifest);

        const fileKey = await importFileKey(fileKeyBytes);
        let written = 0;
        for (const chunkMeta of manifest.chunks) {
            const ciphertext = await input.readChunk(
                chunkMeta.index,
                chunkMeta.ciphertext_sha256,
            );
            if (verifyHashes) {
                const actual = await chunkCiphertextHash(ciphertext);
                if (!constantTimeEqualBase64(actual, chunkMeta.ciphertext_sha256)) {
                    throw new DisIntegrityError(
                        `Chunk ${chunkMeta.index} ciphertext hash mismatch`,
                    );
                }
            }
            const aad = chunkAad(
                ctx,
                manifest.file_revision,
                manifest.manifest_root,
                chunkMeta.index,
                manifest.chunk_count,
            );
            const plaintext = await decryptChunk(ciphertext, fileKey, aad);
            try {
                await input.writeChunk(chunkMeta.index, plaintext);
                written += plaintext.byteLength;
            } finally {
                plaintext.fill(0);
            }
        }
        if (written !== manifest.original_size) {
            throw new DisIntegrityError(
                'Decrypted file size does not match the manifest',
            );
        }
        return { manifestVersion: manifest.version };
    } finally {
        fileKeyBytes.fill(0);
    }
}

export interface UpgradeAttachmentManifestInput {
    readonly context: AttachmentContext;
    readonly manifest: FileManifest;
    /** Unwraps the v1 file key (AAD {@link fileKeyAad}). */
    readonly unwrapFileKey: VaultDecryptBytes;
    /** Re-wraps the file key for v2 (AAD {@link fileKeyAadV2}). */
    readonly wrapFileKey: VaultEncryptBytes;
}

/**
 * Re-seals a legacy v1 manifest as an authenticated v2 manifest.
 *
 * Call this only after {@link decryptAttachment} has successfully processed the
 * whole file; it does not read or re-encrypt chunks. It re-wraps the same file
 * key under the v2 file-key AAD, so a later downgrade to v1 fails at unwrap.
 * The chunk layout, root and revision stay byte-identical, so existing chunk
 * AADs keep verifying. The caller persists the returned manifest.
 */
export async function upgradeAttachmentManifest(
    input: UpgradeAttachmentManifestInput,
): Promise<FileManifestV2> {
    const { manifest, context: ctx } = input;
    if (manifest.version === 2) {
        return manifest;
    }
    validateManifestStructure(manifest);
    await validateManifestConsistency(manifest);

    const fileKeyBytes = await input.unwrapFileKey(
        manifest.wrapped_file_key,
        fileKeyAad(ctx),
    );
    try {
        const wrappedFileKey = await input.wrapFileKey(fileKeyBytes, fileKeyAadV2(ctx));
        const base: Omit<FileManifestV2, 'manifest_mac'> = {
            ...manifest,
            version: 2,
            wrapped_file_key: wrappedFileKey,
        };
        return await sealManifestV2(base, fileKeyBytes, ctx);
    } finally {
        fileKeyBytes.fill(0);
    }
}
