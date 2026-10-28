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

import { decryptString, encryptString } from '../aead/index.js';
import {
    formatEnvelope,
    type VersionedCipherEnvelopeSpec,
} from '../format-versioning/index.js';
import {
    DisInvalidArgumentError,
    DisLegacyPayloadError,
    DisUnsupportedFormatVersionError,
} from '../core/errors.js';

export const VAULT_ITEM_ENVELOPE_V1_PREFIX = 'sv-vault-v1:';
export const VAULT_ITEM_ENVELOPE_V2_PREFIX = 'sv-vault-v2:';
const VAULT_ITEM_ENVELOPE_FAMILY_PREFIX = 'sv-vault-';

/** v1 spec, kept for callers that still produce or inspect the old format. */
export const VAULT_ITEM_ENVELOPE_SPEC: VersionedCipherEnvelopeSpec = {
    currentPrefix: VAULT_ITEM_ENVELOPE_V1_PREFIX,
    familyPrefix: VAULT_ITEM_ENVELOPE_FAMILY_PREFIX,
    subject: 'vault item',
};

/** v2 spec. New writes use this prefix. */
export const VAULT_ITEM_ENVELOPE_V2_SPEC: VersionedCipherEnvelopeSpec = {
    currentPrefix: VAULT_ITEM_ENVELOPE_V2_PREFIX,
    familyPrefix: VAULT_ITEM_ENVELOPE_FAMILY_PREFIX,
    subject: 'vault item',
};

export type VaultEntryData = Record<string, unknown>;

export type VaultEntryEnvelopeVersion = 2 | 1 | 'legacy';

export interface ParsedVaultEntryEnvelope {
    readonly version: VaultEntryEnvelopeVersion;
    readonly payload: string;
}

export interface OpenedVaultEntry {
    readonly plaintext: string;
    readonly version: VaultEntryEnvelopeVersion;
}

/**
 * Parses a vault-item envelope by explicit prefix. Unlike the generic
 * `parseEnvelope` (which models one current version), this understands both
 * released versions and keeps `sv-vault-*` unknown versions fail-closed.
 */
export function parseVaultEntryEnvelope(encryptedData: string): ParsedVaultEntryEnvelope {
    if (typeof encryptedData !== 'string' || encryptedData.length === 0) {
        throw new DisInvalidArgumentError('Vault item ciphertext must be a non-empty string');
    }
    if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V2_PREFIX)) {
        const payload = encryptedData.slice(VAULT_ITEM_ENVELOPE_V2_PREFIX.length);
        if (!payload) {
            throw new DisInvalidArgumentError('Invalid vault item encryption envelope');
        }
        return { version: 2, payload };
    }
    if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)) {
        const payload = encryptedData.slice(VAULT_ITEM_ENVELOPE_V1_PREFIX.length);
        if (!payload) {
            throw new DisInvalidArgumentError('Invalid vault item encryption envelope');
        }
        return { version: 1, payload };
    }
    if (encryptedData.startsWith(VAULT_ITEM_ENVELOPE_FAMILY_PREFIX)) {
        throw new DisUnsupportedFormatVersionError(
            'Unsupported vault item encryption envelope version',
        );
    }
    return { version: 'legacy', payload: encryptedData };
}

/** Returns the envelope version, or `legacy` for an unprefixed payload. */
export function getVaultEntryEnvelopeVersion(
    encryptedData: string,
): VaultEntryEnvelopeVersion {
    return parseVaultEntryEnvelope(encryptedData).version;
}

function requireEntryId(entryId: string): string {
    if (!entryId) {
        throw new DisInvalidArgumentError('entryId is required to bind vault entry ciphertext');
    }
    return entryId;
}

/**
 * Seals a plaintext string in the current envelope. Callers that own their own
 * payload serialisation (e.g. the MSM vault pads before encrypting) can use
 * this directly; {@link encryptVaultEntry} is the JSON convenience wrapper.
 */
export async function sealVaultEntryString(
    plaintext: string,
    key: CryptoKey,
    entryId: string,
): Promise<string> {
    const boundEntryId = requireEntryId(entryId);
    const encrypted = await encryptString(
        plaintext,
        key,
        `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${boundEntryId}`,
    );
    return formatEnvelope(VAULT_ITEM_ENVELOPE_V2_SPEC, encrypted);
}

/**
 * Opens a sealed string. v2 uses the versioned AAD, v1 uses the historical
 * `entryId`-only AAD, and an unprefixed payload is read only through the
 * compatibility path (AAD attempt, then {@link DisLegacyPayloadError}).
 */
export async function openVaultEntryString(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<OpenedVaultEntry> {
    const envelope = parseVaultEntryEnvelope(encryptedData);
    if (envelope.version === 2) {
        const plaintext = await decryptString(
            envelope.payload,
            key,
            `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${requireEntryId(entryId)}`,
        );
        return { plaintext, version: 2 };
    }
    if (envelope.version === 1) {
        const plaintext = await decryptString(
            envelope.payload,
            key,
            requireEntryId(entryId),
        );
        return { plaintext, version: 1 };
    }
    if (entryId) {
        try {
            const plaintext = await decryptString(envelope.payload, key, entryId);
            return { plaintext, version: 'legacy' };
        } catch {
            throw new DisLegacyPayloadError('Legacy vault item without AAD requires migration.');
        }
    }
    throw new DisLegacyPayloadError('Legacy vault item without AAD requires migration.');
}

/** Seals a vault entry, binding it to `entryId` via AEAD associated data. */
export async function encryptVaultEntry(
    data: VaultEntryData,
    key: CryptoKey,
    entryId: string,
): Promise<string> {
    return sealVaultEntryString(JSON.stringify(data), key, entryId);
}

/**
 * Opens a vault entry. v2 and v1 are read with their respective AAD; legacy
 * no-AAD payloads throw {@link DisLegacyPayloadError} on the runtime path.
 */
export async function decryptVaultEntry(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<VaultEntryData> {
    const opened = await openVaultEntryString(encryptedData, key, entryId);
    return JSON.parse(opened.plaintext) as VaultEntryData;
}

export interface VaultEntryMigrationResult {
    readonly data: VaultEntryData;
    readonly legacyEnvelopeUsed: boolean;
    readonly legacyNoAadFallbackUsed: boolean;
}

/**
 * Decrypts an entry on an explicit migration path, permitting the no-AAD
 * fallback for the oldest payloads so they can be rewritten as versioned,
 * AAD-bound items. Never use on the normal runtime read path.
 */
export async function decryptVaultEntryForMigration(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<VaultEntryMigrationResult> {
    const envelope = parseVaultEntryEnvelope(encryptedData);
    if (envelope.version === 2) {
        return {
            data: JSON.parse(
                await decryptString(
                    envelope.payload,
                    key,
                    `${VAULT_ITEM_ENVELOPE_V2_PREFIX}${requireEntryId(entryId)}`,
                ),
            ) as VaultEntryData,
            legacyEnvelopeUsed: false,
            legacyNoAadFallbackUsed: false,
        };
    }
    if (envelope.version === 1) {
        return {
            data: JSON.parse(
                await decryptString(envelope.payload, key, requireEntryId(entryId)),
            ) as VaultEntryData,
            legacyEnvelopeUsed: true,
            legacyNoAadFallbackUsed: false,
        };
    }
    if (entryId) {
        try {
            return {
                data: JSON.parse(
                    await decryptString(envelope.payload, key, entryId),
                ) as VaultEntryData,
                legacyEnvelopeUsed: true,
                legacyNoAadFallbackUsed: false,
            };
        } catch {
            // Fall through to the no-AAD fallback below.
        }
    }
    const data = JSON.parse(await decryptString(envelope.payload, key)) as VaultEntryData;
    return { data, legacyEnvelopeUsed: true, legacyNoAadFallbackUsed: true };
}

/** True if `encryptedData` is a current (v2) vault-item envelope. */
export function isCurrentVaultEntryEnvelope(encryptedData: string): boolean {
    return getVaultEntryEnvelopeVersion(encryptedData) === 2;
}
