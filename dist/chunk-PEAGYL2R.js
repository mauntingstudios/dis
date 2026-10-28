import { sha256JsonBase64, sha256Base64, constantTimeEqualBase64, hmacSha256 } from './chunk-MPWYZXW7.js';
import { randomBytes } from './chunk-NGBC4E73.js';
import { importAesGcmKey, deriveHkdfSha256Bits } from './chunk-OPHN2B3N.js';
import { encryptBytes, decryptBytes } from './chunk-U65A4HIY.js';
import { AES_KEY_LENGTH } from './chunk-BUFRR5PB.js';
import { concatBytes, utf8ToBytes, bytesToBase64 } from './chunk-JSKIWIEC.js';
import { DisInvalidArgumentError, DisIntegrityError } from './chunk-MJO7IJZC.js';

// src/file-encryption/index.ts
var DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;
var FILE_MANIFEST_V1_PREFIX = "sv-file-manifest-v1:";
function manifestAad(ctx) {
  return `sv-file-manifest-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}
function manifestMacContext(ctx) {
  return `sv-file-manifest-mac-v2:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}
function fileKeyAad(ctx) {
  return `sv-file-key-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}
function fileKeyAadV2(ctx) {
  return `sv-file-key-v2:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}
function chunkAad(ctx, fileRevision, manifestRoot, chunkIndex, chunkCount) {
  return `sv-file-chunk-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}:${fileRevision}:${manifestRoot}:${chunkIndex}:${chunkCount}`;
}
var MANIFEST_MAC_DOMAIN = "sv-file-manifest-v2";
var MANIFEST_MAC_INFO_PREFIX = "sv-file-manifest-mac-v2:";
var AAD_SEPARATOR = new Uint8Array([0]);
function canonicalManifestBytes(manifest) {
  const fields = [
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
      chunk.ciphertext_sha256
    ]),
    manifest.preview,
    manifest.notes
  ];
  return utf8ToBytes(JSON.stringify(fields));
}
async function deriveManifestMacKey(fileKeyBytes, ctx) {
  return deriveHkdfSha256Bits(fileKeyBytes, {
    info: utf8ToBytes(`${MANIFEST_MAC_INFO_PREFIX}${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`),
    lengthBits: 256
  });
}
async function computeManifestMac(fileKeyBytes, ctx, manifest) {
  const macKey = await deriveManifestMacKey(fileKeyBytes, ctx);
  try {
    const payload = concatBytes(
      utf8ToBytes(MANIFEST_MAC_DOMAIN),
      AAD_SEPARATOR,
      utf8ToBytes(manifestMacContext(ctx)),
      AAD_SEPARATOR,
      canonicalManifestBytes(manifest)
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
async function verifyManifestMac(fileKeyBytes, ctx, manifest) {
  const expected = await computeManifestMac(fileKeyBytes, ctx, manifest);
  let matches = false;
  try {
    matches = constantTimeEqualBase64(expected, manifest.manifest_mac);
  } catch {
    matches = false;
  }
  if (!matches) {
    throw new DisIntegrityError("File manifest authentication failed");
  }
}
async function sealManifestV2(manifest, fileKeyBytes, ctx) {
  const manifestMac = await computeManifestMac(fileKeyBytes, ctx, manifest);
  return { ...manifest, manifest_mac: manifestMac };
}
function requireString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new DisInvalidArgumentError(`${field} must be a non-empty string`);
  }
  return value;
}
function requireNonNegativeInt(value, field) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new DisInvalidArgumentError(`${field} must be a non-negative integer`);
  }
  return value;
}
function requirePositiveInt(value, field) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new DisInvalidArgumentError(`${field} must be a positive integer`);
  }
  return value;
}
function validateManifestStructure(manifest) {
  if (!manifest || typeof manifest !== "object") {
    throw new DisInvalidArgumentError("File manifest must be an object");
  }
  if (manifest.version !== 1 && manifest.version !== 2) {
    throw new DisInvalidArgumentError("Unsupported file manifest version");
  }
  if (manifest.algorithm !== "AES-256-GCM") {
    throw new DisInvalidArgumentError("Unsupported file manifest algorithm");
  }
  requireString(manifest.file_id, "file_id");
  requireString(manifest.manifest_root, "manifest_root");
  requireString(manifest.owner_id, "owner_id");
  requireString(manifest.vault_item_id, "vault_item_id");
  requireString(manifest.original_name, "original_name");
  requireString(manifest.uploaded_at, "uploaded_at");
  requireString(manifest.wrapped_file_key, "wrapped_file_key");
  if (manifest.mime_type !== null && typeof manifest.mime_type !== "string") {
    throw new DisInvalidArgumentError("mime_type must be a string or null");
  }
  if (manifest.previous_manifest_hash !== null && typeof manifest.previous_manifest_hash !== "string") {
    throw new DisInvalidArgumentError("previous_manifest_hash must be a string or null");
  }
  if (manifest.last_modified !== null) {
    requireNonNegativeInt(manifest.last_modified, "last_modified");
  }
  requireNonNegativeInt(manifest.file_revision, "file_revision");
  requireNonNegativeInt(manifest.original_size, "original_size");
  requirePositiveInt(manifest.chunk_size, "chunk_size");
  requirePositiveInt(manifest.chunk_count, "chunk_count");
  if (!Array.isArray(manifest.chunks)) {
    throw new DisInvalidArgumentError("chunks must be an array");
  }
  if (manifest.chunks.length !== manifest.chunk_count) {
    throw new DisInvalidArgumentError("chunk_count does not match the chunk list");
  }
  for (let index = 0; index < manifest.chunks.length; index += 1) {
    const chunk = manifest.chunks[index];
    if (!chunk || typeof chunk !== "object" || chunk.index !== index) {
      throw new DisInvalidArgumentError(`chunks[${index}] is malformed or out of order`);
    }
    requireNonNegativeInt(chunk.plaintext_size, `chunks[${index}].plaintext_size`);
    requireNonNegativeInt(chunk.ciphertext_size, `chunks[${index}].ciphertext_size`);
    requireString(chunk.ciphertext_sha256, `chunks[${index}].ciphertext_sha256`);
  }
  if (manifest.version === 2) {
    requireString(manifest.manifest_mac, "manifest_mac");
  }
}
async function validateManifestConsistency(manifest) {
  const originalSize = manifest.chunks.reduce(
    (total, chunk) => total + chunk.plaintext_size,
    0
  );
  if (originalSize !== manifest.original_size) {
    throw new DisIntegrityError("File manifest size does not match the chunk list");
  }
  const expectedCount = Math.max(1, Math.ceil(manifest.original_size / manifest.chunk_size));
  if (manifest.chunk_count !== expectedCount) {
    throw new DisIntegrityError("File manifest chunk count does not match its size");
  }
  const expectedRoot = await computeManifestRoot({
    fileId: manifest.file_id,
    fileRevision: manifest.file_revision,
    chunkSize: manifest.chunk_size,
    chunkCount: manifest.chunk_count,
    chunks: manifest.chunks.map((chunk) => ({
      index: chunk.index,
      plaintext_size: chunk.plaintext_size
    }))
  });
  if (!constantTimeEqualBase64(expectedRoot, manifest.manifest_root)) {
    throw new DisIntegrityError("File manifest root does not match the chunk list");
  }
}
function generateFileKeyBytes() {
  return randomBytes(AES_KEY_LENGTH);
}
function importFileKey(rawKey) {
  return importAesGcmKey(rawKey);
}
async function encryptChunk(plaintext, fileKey, aad) {
  try {
    return await encryptBytes(plaintext, fileKey, aad);
  } finally {
    plaintext.fill(0);
  }
}
async function decryptChunk(encryptedBase64, fileKey, aad) {
  return decryptBytes(encryptedBase64, fileKey, aad);
}
async function computeManifestRoot(input) {
  return sha256JsonBase64({
    file_id: input.fileId,
    file_revision: input.fileRevision,
    chunk_size: input.chunkSize,
    chunk_count: input.chunkCount,
    chunks: input.chunks.map((c) => ({
      index: c.index,
      storage_path: void 0,
      plaintext_size: c.plaintext_size
    }))
  });
}
function chunkCiphertextHash(ciphertextBase64) {
  return sha256Base64(new TextEncoder().encode(ciphertextBase64));
}
async function encryptAttachment(input) {
  const chunkSize = input.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (chunkSize <= 0) throw new DisInvalidArgumentError("chunkSize must be positive");
  const fileRevision = input.fileRevision ?? 1;
  const chunkCount = Math.max(1, Math.ceil(input.totalSize / chunkSize));
  const ctx = input.context;
  const plannedChunks = Array.from({ length: chunkCount }, (_, index) => {
    const start = index * chunkSize;
    const end = Math.min(input.totalSize, start + chunkSize);
    return { index, plaintext_size: end - start };
  });
  const manifestRoot = await computeManifestRoot({
    fileId: ctx.fileId,
    fileRevision,
    chunkSize,
    chunkCount,
    chunks: plannedChunks
  });
  const fileKeyBytes = generateFileKeyBytes();
  const fileKey = await importFileKey(fileKeyBytes);
  const chunks = [];
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
        plaintext_size: plannedChunks[index].plaintext_size,
        ciphertext_size: ciphertextSize,
        ciphertext_sha256: await chunkCiphertextHash(ciphertext)
      });
    }
    const manifest = await sealManifestV2(
      {
        version: 2,
        algorithm: "AES-256-GCM",
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
        uploaded_at: (/* @__PURE__ */ new Date()).toISOString(),
        chunk_size: chunkSize,
        chunk_count: chunkCount,
        wrapped_file_key: wrappedFileKey,
        chunks,
        preview: null,
        notes: null
      },
      fileKeyBytes,
      ctx
    );
    return { manifest, manifestRoot };
  } finally {
    fileKeyBytes.fill(0);
  }
}
async function decryptAttachment(input) {
  const { manifest, context: ctx } = input;
  validateManifestStructure(manifest);
  const verifyHashes = input.verifyChunkHashes ?? true;
  const fileKeyBytes = await input.unwrapFileKey(
    manifest.wrapped_file_key,
    manifest.version === 2 ? fileKeyAadV2(ctx) : fileKeyAad(ctx)
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
        chunkMeta.ciphertext_sha256
      );
      if (verifyHashes) {
        const actual = await chunkCiphertextHash(ciphertext);
        if (!constantTimeEqualBase64(actual, chunkMeta.ciphertext_sha256)) {
          throw new DisIntegrityError(
            `Chunk ${chunkMeta.index} ciphertext hash mismatch`
          );
        }
      }
      const aad = chunkAad(
        ctx,
        manifest.file_revision,
        manifest.manifest_root,
        chunkMeta.index,
        manifest.chunk_count
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
        "Decrypted file size does not match the manifest"
      );
    }
    return { manifestVersion: manifest.version };
  } finally {
    fileKeyBytes.fill(0);
  }
}
async function upgradeAttachmentManifest(input) {
  const { manifest, context: ctx } = input;
  if (manifest.version === 2) {
    return manifest;
  }
  validateManifestStructure(manifest);
  await validateManifestConsistency(manifest);
  const fileKeyBytes = await input.unwrapFileKey(
    manifest.wrapped_file_key,
    fileKeyAad(ctx)
  );
  try {
    const wrappedFileKey = await input.wrapFileKey(fileKeyBytes, fileKeyAadV2(ctx));
    const base = {
      ...manifest,
      version: 2,
      wrapped_file_key: wrappedFileKey
    };
    return await sealManifestV2(base, fileKeyBytes, ctx);
  } finally {
    fileKeyBytes.fill(0);
  }
}

export { DEFAULT_CHUNK_SIZE, FILE_MANIFEST_V1_PREFIX, chunkAad, chunkCiphertextHash, computeManifestRoot, decryptAttachment, decryptChunk, encryptAttachment, encryptChunk, fileKeyAad, fileKeyAadV2, generateFileKeyBytes, importFileKey, manifestAad, manifestMacContext, upgradeAttachmentManifest };
//# sourceMappingURL=chunk-PEAGYL2R.js.map
//# sourceMappingURL=chunk-PEAGYL2R.js.map