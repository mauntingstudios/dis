/**
 * Post-quantum hybrid key wrapping (ML-KEM-768 + RSA-4096) — round-trip,
 * negative, and legacy golden-vector tests.
 *
 * The GOLDEN VECTOR below was produced by the legacy Singra pqCryptoService
 * (version byte 0x04, HKDF-v2). It proves DIS decrypts already-stored hybrid
 * sharing/emergency-key ciphertext byte-for-byte. A failure here means the
 * apps can no longer read shared-collection / emergency-access keys.
 */
import { describe, expect, it } from "vitest";
import {
    generateHybridKeyPair,
    generatePQKeyPair,
    hybridEncrypt,
    hybridDecrypt,
    hybridWrapKey,
    hybridUnwrapKey,
    isHybridEncrypted,
    isCurrentStandardEncrypted,
    migrateToHybrid,
    buildSharedKeyWrapAad,
} from "../index.js";
import { setCryptoProvider } from "../core/provider.js";
import { LEGACY_HYBRID_VECTOR as LEGACY } from "./__fixtures__/legacy-hybrid.js";

describe("post-quantum hybrid", () => {
    it("round-trips hybridEncrypt -> hybridDecrypt with AAD", async () => {
        const kp = await generateHybridKeyPair();
        const aad = buildSharedKeyWrapAad({
            collectionId: "c1",
            senderUserId: "s1",
            recipientUserId: "r1",
            keyVersion: 1,
        });
        const ct = await hybridWrapKey("super-secret-shared-key", kp.pqPublicKey, kp.rsaPublicKey, aad);
        expect(isHybridEncrypted(ct)).toBe(true);
        expect(isCurrentStandardEncrypted(ct)).toBe(true);
        expect(await hybridUnwrapKey(ct, kp.pqSecretKey, kp.rsaPrivateKey, aad)).toBe("super-secret-shared-key");
    });

    it("fails closed on wrong AAD", async () => {
        const kp = await generateHybridKeyPair();
        const ct = await hybridEncrypt("x", kp.pqPublicKey, kp.rsaPublicKey, "aad-A");
        await expect(hybridDecrypt(ct, kp.pqSecretKey, kp.rsaPrivateKey, "aad-B")).rejects.toThrow();
    });

    it("fails closed on tampered ciphertext", async () => {
        const kp = await generateHybridKeyPair();
        const ct = await hybridEncrypt("x", kp.pqPublicKey, kp.rsaPublicKey, "aad");
        const raw = Uint8Array.from(Buffer.from(ct, "base64"));
        raw[raw.length - 1] ^= 0xff;
        const tampered = Buffer.from(raw).toString("base64");
        await expect(hybridDecrypt(tampered, kp.pqSecretKey, kp.rsaPrivateKey, "aad")).rejects.toThrow();
    });

    it("GOLDEN: DIS decrypts a legacy-produced v0x04 hybrid ciphertext", async () => {
        expect(isCurrentStandardEncrypted(LEGACY.ciphertext)).toBe(true);
        const out = await hybridDecrypt(
            LEGACY.ciphertext,
            LEGACY.pqSecretKey,
            LEGACY.rsaPrivateKey,
            LEGACY.aad,
        );
        expect(out).toBe(LEGACY.plaintext);
    });

    it("uses the configured crypto provider for PQ key generation", () => {
        const original = globalThis.crypto;
        const seed = new Uint8Array(64).fill(7);
        setCryptoProvider({
            getRandomValues: ((view: Uint8Array) => {
                view.set(seed.subarray(0, view.length));
                return view;
            }) as typeof original.getRandomValues,
            subtle: original.subtle,
        });
        try {
            const first = generatePQKeyPair();
            const second = generatePQKeyPair();
            expect(first.publicKey).toBe(second.publicKey);
            expect(first.secretKey).toBe(second.secretKey);
        } finally {
            setCryptoProvider(null);
        }
    });

    it("distinguishes the current version byte from a legacy one", async () => {
        const kp = await generateHybridKeyPair();
        const ciphertext = await hybridEncrypt(
            "x",
            kp.pqPublicKey,
            kp.rsaPublicKey,
            "aad",
        );
        const raw = Uint8Array.from(Buffer.from(ciphertext, "base64"));
        raw[0] = 0x03;
        const legacy = Buffer.from(raw).toString("base64");
        expect(isHybridEncrypted(legacy)).toBe(true);
        expect(isCurrentStandardEncrypted(legacy)).toBe(false);
        await expect(
            hybridDecrypt(legacy, kp.pqSecretKey, kp.rsaPrivateKey, "aad"),
        ).rejects.toThrow();
    });

    it("leaves an already-current ciphertext unchanged and verifies its AAD", async () => {
        const kp = await generateHybridKeyPair();
        const aad = buildSharedKeyWrapAad({
            collectionId: "c1",
            senderUserId: "s1",
            recipientUserId: "r1",
            keyVersion: 1,
        });
        const ciphertext = await hybridWrapKey(
            "shared-key",
            kp.pqPublicKey,
            kp.rsaPublicKey,
            aad,
        );
        await expect(
            migrateToHybrid(
                ciphertext,
                kp.rsaPrivateKey,
                kp.pqSecretKey,
                kp.pqPublicKey,
                kp.rsaPublicKey,
                aad,
            ),
        ).resolves.toBe(ciphertext);

        await expect(
            migrateToHybrid(
                ciphertext,
                kp.rsaPrivateKey,
                kp.pqSecretKey,
                kp.pqPublicKey,
                kp.rsaPublicKey,
                "wrong-aad",
            ),
        ).rejects.toThrow();
    });
});
