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
/** Default chunk size (4 MiB), matching the Singra Premium format. */
declare const DEFAULT_CHUNK_SIZE: number;
/** Legacy manifest prefix. Manifests are objects with a `version` field, not wrapped strings. */
declare const FILE_MANIFEST_V1_PREFIX = "sv-file-manifest-v1:";
/** Opaque binding context for an attachment. Ids are treated as opaque strings. */
interface AttachmentContext {
    readonly ownerId: string;
    readonly vaultItemId: string;
    readonly fileId: string;
}
/** Encrypts text with the outer vault key (e.g. DIS aead.encryptString). */
type VaultEncryptText = (plaintext: string, aad?: string) => Promise<string>;
type VaultDecryptText = (encrypted: string, aad?: string) => Promise<string>;
type VaultEncryptBytes = (plaintext: Uint8Array, aad?: string) => Promise<string>;
type VaultDecryptBytes = (encrypted: string, aad?: string) => Promise<Uint8Array>;
interface FileChunkManifest {
    readonly index: number;
    readonly plaintext_size: number;
    readonly ciphertext_size: number;
    readonly ciphertext_sha256: string;
}
interface FileManifestV1 {
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
interface FileManifestV2 extends Omit<FileManifestV1, 'version'> {
    readonly version: 2;
    readonly manifest_mac: string;
}
type FileManifest = FileManifestV1 | FileManifestV2;
/**
 * @deprecated The v2 manifest authenticates through {@link manifestMacContext}.
 * Kept for compatibility with callers that used the v1 domain string.
 */
declare function manifestAad(ctx: AttachmentContext): string;
/** Domain-separated HMAC context for the v2 manifest. */
declare function manifestMacContext(ctx: AttachmentContext): string;
/** v1 file-key AAD. Kept for reading legacy manifests. */
declare function fileKeyAad(ctx: AttachmentContext): string;
/** v2 file-key AAD. Binds the manifest version to the wrapped file key. */
declare function fileKeyAadV2(ctx: AttachmentContext): string;
declare function chunkAad(ctx: AttachmentContext, fileRevision: number, manifestRoot: string, chunkIndex: number, chunkCount: number): string;
/** Generates fresh per-file AES-256 key bytes (caller must wipe). */
declare function generateFileKeyBytes(): Uint8Array;
/** Imports raw file-key bytes as a non-extractable AES-GCM key. */
declare function importFileKey(rawKey: Uint8Array): Promise<CryptoKey>;
/** Seals one plaintext chunk. `plaintext` is wiped before returning. */
declare function encryptChunk(plaintext: Uint8Array, fileKey: CryptoKey, aad: string): Promise<string>;
/** Opens one chunk. Returned bytes are plaintext — caller must wipe. */
declare function decryptChunk(encryptedBase64: string, fileKey: CryptoKey, aad: string): Promise<Uint8Array>;
interface PlannedChunk {
    readonly index: number;
    readonly plaintext_size: number;
}
/**
 * Computes the manifest root: a SHA-256 over the planned chunk layout. Binding
 * each chunk's AAD to this root prevents chunk-count / size tampering.
 */
declare function computeManifestRoot(input: {
    fileId: string;
    fileRevision: number;
    chunkSize: number;
    chunkCount: number;
    chunks: readonly PlannedChunk[];
}): Promise<string>;
/** SHA-256 (base64) of a ciphertext chunk, for the manifest. */
declare function chunkCiphertextHash(ciphertextBase64: string): Promise<string>;
interface EncryptAttachmentInput {
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
interface EncryptAttachmentResult {
    readonly manifest: FileManifestV2;
    readonly manifestRoot: string;
}
/**
 * Encrypts an attachment chunk-by-chunk and produces an authenticated manifest.
 * Storage is delegated to `readChunk`/`writeChunk`. The returned manifest's
 * `wrapped_file_key` is bound to the file via {@link fileKeyAad}.
 */
declare function encryptAttachment(input: EncryptAttachmentInput): Promise<EncryptAttachmentResult>;
interface DecryptAttachmentInput {
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
interface DecryptAttachmentResult {
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
declare function decryptAttachment(input: DecryptAttachmentInput): Promise<DecryptAttachmentResult>;
interface UpgradeAttachmentManifestInput {
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
declare function upgradeAttachmentManifest(input: UpgradeAttachmentManifestInput): Promise<FileManifestV2>;

export { type AttachmentContext, DEFAULT_CHUNK_SIZE, type DecryptAttachmentInput, type DecryptAttachmentResult, type EncryptAttachmentInput, type EncryptAttachmentResult, FILE_MANIFEST_V1_PREFIX, type FileChunkManifest, type FileManifest, type FileManifestV1, type FileManifestV2, type UpgradeAttachmentManifestInput, type VaultDecryptBytes, type VaultDecryptText, type VaultEncryptBytes, type VaultEncryptText, chunkAad, chunkCiphertextHash, computeManifestRoot, decryptAttachment, decryptChunk, encryptAttachment, encryptChunk, fileKeyAad, fileKeyAadV2, generateFileKeyBytes, importFileKey, manifestAad, manifestMacContext, upgradeAttachmentManifest };
