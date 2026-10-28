import { VersionedCipherEnvelopeSpec } from '../format-versioning/index.js';

/**
 * dis-vault-encryption — encryption of structured vault entries.
 *
 * A vault entry is an arbitrary JSON-serialisable record. Version 2 seals it
 * with AES-256-GCM under the `sv-vault-v2:` envelope and uses
 * `sv-vault-v2:<entryId>` as associated data, so the version label itself is
 * authenticated. Version 1 (`sv-vault-v1:`) used only `entryId` as AAD; it is
 * still read for compatibility, which also means a v1 payload can still be
 * stripped of its prefix and read through the legacy path. New writes always
 * use v2.
 *
 * Legacy (pre-versioning, no-AAD) payloads fail closed on the runtime read
 * path and are only readable through the explicit migration helper.
 */

declare const VAULT_ITEM_ENVELOPE_V1_PREFIX = "sv-vault-v1:";
declare const VAULT_ITEM_ENVELOPE_V2_PREFIX = "sv-vault-v2:";
/** v1 spec, kept for callers that still produce or inspect the old format. */
declare const VAULT_ITEM_ENVELOPE_SPEC: VersionedCipherEnvelopeSpec;
/** v2 spec. New writes use this prefix. */
declare const VAULT_ITEM_ENVELOPE_V2_SPEC: VersionedCipherEnvelopeSpec;
type VaultEntryData = Record<string, unknown>;
type VaultEntryEnvelopeVersion = 2 | 1 | 'legacy';
interface ParsedVaultEntryEnvelope {
    readonly version: VaultEntryEnvelopeVersion;
    readonly payload: string;
}
interface OpenedVaultEntry {
    readonly plaintext: string;
    readonly version: VaultEntryEnvelopeVersion;
}
/**
 * Parses a vault-item envelope by explicit prefix. Unlike the generic
 * `parseEnvelope` (which models one current version), this understands both
 * released versions and keeps `sv-vault-*` unknown versions fail-closed.
 */
declare function parseVaultEntryEnvelope(encryptedData: string): ParsedVaultEntryEnvelope;
/** Returns the envelope version, or `legacy` for an unprefixed payload. */
declare function getVaultEntryEnvelopeVersion(encryptedData: string): VaultEntryEnvelopeVersion;
/**
 * Seals a plaintext string in the current envelope. Callers that own their own
 * payload serialisation (e.g. the MSM vault pads before encrypting) can use
 * this directly; {@link encryptVaultEntry} is the JSON convenience wrapper.
 */
declare function sealVaultEntryString(plaintext: string, key: CryptoKey, entryId: string): Promise<string>;
/**
 * Opens a sealed string. v2 uses the versioned AAD, v1 uses the historical
 * `entryId`-only AAD, and an unprefixed payload is read only through the
 * compatibility path (AAD attempt, then {@link DisLegacyPayloadError}).
 */
declare function openVaultEntryString(encryptedData: string, key: CryptoKey, entryId: string): Promise<OpenedVaultEntry>;
/** Seals a vault entry, binding it to `entryId` via AEAD associated data. */
declare function encryptVaultEntry(data: VaultEntryData, key: CryptoKey, entryId: string): Promise<string>;
/**
 * Opens a vault entry. v2 and v1 are read with their respective AAD; legacy
 * no-AAD payloads throw {@link DisLegacyPayloadError} on the runtime path.
 */
declare function decryptVaultEntry(encryptedData: string, key: CryptoKey, entryId: string): Promise<VaultEntryData>;
interface VaultEntryMigrationResult {
    readonly data: VaultEntryData;
    readonly legacyEnvelopeUsed: boolean;
    readonly legacyNoAadFallbackUsed: boolean;
}
/**
 * Decrypts an entry on an explicit migration path, permitting the no-AAD
 * fallback for the oldest payloads so they can be rewritten as versioned,
 * AAD-bound items. Never use on the normal runtime read path.
 */
declare function decryptVaultEntryForMigration(encryptedData: string, key: CryptoKey, entryId: string): Promise<VaultEntryMigrationResult>;
/** True if `encryptedData` is a current (v2) vault-item envelope. */
declare function isCurrentVaultEntryEnvelope(encryptedData: string): boolean;

export { type OpenedVaultEntry, type ParsedVaultEntryEnvelope, VAULT_ITEM_ENVELOPE_SPEC, VAULT_ITEM_ENVELOPE_V1_PREFIX, VAULT_ITEM_ENVELOPE_V2_PREFIX, VAULT_ITEM_ENVELOPE_V2_SPEC, type VaultEntryData, type VaultEntryEnvelopeVersion, type VaultEntryMigrationResult, decryptVaultEntry, decryptVaultEntryForMigration, encryptVaultEntry, getVaultEntryEnvelopeVersion, isCurrentVaultEntryEnvelope, openVaultEntryString, parseVaultEntryEnvelope, sealVaultEntryString };
