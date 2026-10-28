import { encryptString, decryptString } from './chunk-U65A4HIY.js';
import { formatEnvelope } from './chunk-SCHZI6YY.js';
import { DisInvalidArgumentError, DisUnsupportedFormatVersionError, DisLegacyPayloadError } from './chunk-MJO7IJZC.js';

// src/vault-encryption/index.ts
var VAULT_ITEM_ENVELOPE_V1_PREFIX = "sv-vault-v1:";
var VAULT_ITEM_ENVELOPE_V2_PREFIX = "sv-vault-v2:";
var VAULT_ITEM_ENVELOPE_FAMILY_PREFIX = "sv-vault-";
var VAULT_ITEM_ENVELOPE_SPEC = {
  currentPrefix: VAULT_ITEM_ENVELOPE_V1_PREFIX,
  familyPrefix: VAULT_ITEM_ENVELOPE_FAMILY_PREFIX,
  subject: "vault item"
};
var VAULT_ITEM_ENVELOPE_V2_SPEC = {
  currentPrefix: VAULT_ITEM_ENVELOPE_V2_PREFIX,
  familyPrefix: VAULT_ITEM_ENVELOPE_FAMILY_PREFIX,
  subject: "vault item"
};
function parseVaultEntryEnvelope(encryptedData) {
  if (typeof encryptedData !== "string" || encryptedData.length === 0) {
    throw new DisInvalidArgumentError("Vault item ciphertext must be a non-empty string");
  }
  if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V2_PREFIX)) {
    const payload = encryptedData.slice(VAULT_ITEM_ENVELOPE_V2_PREFIX.length);
    if (!payload) {
      throw new DisInvalidArgumentError("Invalid vault item encryption envelope");
    }
    return { version: 2, payload };
  }
  if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)) {
    const payload = encryptedData.slice(VAULT_ITEM_ENVELOPE_V1_PREFIX.length);
    if (!payload) {
      throw new DisInvalidArgumentError("Invalid vault item encryption envelope");
    }
    return { version: 1, payload };
  }
  if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_FAMILY_PREFIX)) {
    throw new DisUnsupportedFormatVersionError(
      "Unsupported vault item encryption envelope version"
    );
  }
  return { version: "legacy", payload: encryptedData };
}
function getVaultEntryEnvelopeVersion(encryptedData) {
  return parseVaultEntryEnvelope(encryptedData).version;
}
function requireEntryId(entryId) {
  if (!entryId) {
    throw new DisInvalidArgumentError("entryId is required to bind vault entry ciphertext");
  }
  return entryId;
}
async function sealVaultEntryString(plaintext, key, entryId) {
  const boundEntryId = requireEntryId(entryId);
  const encrypted = await encryptString(
    plaintext,
    key,
    `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${boundEntryId}`
  );
  return formatEnvelope(VAULT_ITEM_ENVELOPE_V2_SPEC, encrypted);
}
async function openVaultEntryString(encryptedData, key, entryId) {
  const envelope = parseVaultEntryEnvelope(encryptedData);
  if (envelope.version === 2) {
    const plaintext = await decryptString(
      envelope.payload,
      key,
      `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${requireEntryId(entryId)}`
    );
    return { plaintext, version: 2 };
  }
  if (envelope.version === 1) {
    const plaintext = await decryptString(
      envelope.payload,
      key,
      requireEntryId(entryId)
    );
    return { plaintext, version: 1 };
  }
  if (entryId) {
    try {
      const plaintext = await decryptString(envelope.payload, key, entryId);
      return { plaintext, version: "legacy" };
    } catch {
      throw new DisLegacyPayloadError("Legacy vault item without AAD requires migration.");
    }
  }
  throw new DisLegacyPayloadError("Legacy vault item without AAD requires migration.");
}
async function encryptVaultEntry(data, key, entryId) {
  return sealVaultEntryString(JSON.stringify(data), key, entryId);
}
async function decryptVaultEntry(encryptedData, key, entryId) {
  const opened = await openVaultEntryString(encryptedData, key, entryId);
  return JSON.parse(opened.plaintext);
}
async function decryptVaultEntryForMigration(encryptedData, key, entryId) {
  const envelope = parseVaultEntryEnvelope(encryptedData);
  if (envelope.version === 2) {
    return {
      data: JSON.parse(
        await decryptString(
          envelope.payload,
          key,
          `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${requireEntryId(entryId)}`
        )
      ),
      legacyEnvelopeUsed: false,
      legacyNoAadFallbackUsed: false
    };
  }
  if (envelope.version === 1) {
    return {
      data: JSON.parse(
        await decryptString(envelope.payload, key, requireEntryId(entryId))
      ),
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: false
    };
  }
  if (entryId) {
    try {
      return {
        data: JSON.parse(
          await decryptString(envelope.payload, key, entryId)
        ),
        legacyEnvelopeUsed: true,
        legacyNoAadFallbackUsed: false
      };
    } catch {
    }
  }
  const data = JSON.parse(await decryptString(envelope.payload, key));
  return { data, legacyEnvelopeUsed: true, legacyNoAadFallbackUsed: true };
}
function isCurrentVaultEntryEnvelope(encryptedData) {
  return getVaultEntryEnvelopeVersion(encryptedData) === 2;
}

export { VAULT_ITEM_ENVELOPE_SPEC, VAULT_ITEM_ENVELOPE_V1_PREFIX, VAULT_ITEM_ENVELOPE_V2_PREFIX, VAULT_ITEM_ENVELOPE_V2_SPEC, decryptVaultEntry, decryptVaultEntryForMigration, encryptVaultEntry, getVaultEntryEnvelopeVersion, isCurrentVaultEntryEnvelope, openVaultEntryString, parseVaultEntryEnvelope, sealVaultEntryString };
//# sourceMappingURL=chunk-OKJJMNND.js.map
//# sourceMappingURL=chunk-OKJJMNND.js.map