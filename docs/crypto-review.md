# Crypto Review

Review of the cryptographic choices DIS inherits from Singra and exposes. Each
item is rated and justified. Claims are backed by code/tests in this repo or
flagged `not verified`.

## Primitives

| Choice | Assessment | Notes |
| --- | --- | --- |
| **Argon2id** (memory-hard KDF) | Sound | Versioned params: v1 = 64 MiB, v2 = 128 MiB, t=3, p=4, 32-byte output. Memory-hard, resists GPU/ASIC. Upgrade path via version field. |
| **AES-256-GCM** AEAD | Sound | 96-bit random IV (correct length for GCM), 128-bit tag. Confidentiality + integrity + AAD. |
| **96-bit random IV** | Sound with caveat | Random IVs are safe for GCM up to ~2³² messages **per key**. Content-key is per-user; volumes are far below the birthday bound. Each call draws a fresh CSPRNG IV (tested). |
| **HKDF-SHA-256** for key separation | Sound | Domain-separated `info` per purpose (wrap-key, device-key). Zero salt acceptable because IKM (Argon2id output / device key) is already high-entropy. |
| **Content-key indirection** (UserKey) | Good design | Password change re-wraps the content key only; no bulk re-encryption; limits exposure of the password-derived key. |
| **Entry-id AAD on vault items** | Good | Binds ciphertext to its logical slot; defeats cross-row swap. |
| **Per-file random key + chunk AAD** | Good | File key wrapped under content key; chunk AAD binds owner/item/file/revision/manifest-root/index/count. Manifest v2 additionally authenticates the full chunk list and metadata, so reorder, splice, cross-file reuse and truncation are detected. v1 manifests are legacy and are not truncation-protected. |
| **SHA-256 manifest root + per-chunk hash** | Good | The root is recomputed on read (v1 and v2); per-chunk hashes detect storage-level tampering independent of the GCM tag. |
| **ML-KEM-768 + RSA-OAEP hybrid** (sharing) | Forward-looking | Hybrid protects against "harvest now, decrypt later"; classical RSA retained for defence in depth. Versioned blob layout. _Port to DIS in phase 2._ |
| **Non-extractable CryptoKeys** | Good, with one documented exception | Imported keys cannot be exported from WebCrypto — except the `messaging` ratchet key pair, which must be extractable so a session can be persisted and resumed. See R-5 in `threat-model.md`. |
| **Double Ratchet** (ECDH P-256 + HKDF-SHA-256 + AES-256-GCM) | Sound composition | Published algorithm, no invented parts. Symmetric ratchet gives forward secrecy; DH ratchet gives post-compromise security. Root/chain/message KDF stages are domain-separated (`sv-dr-root-v1` / `sv-dr-chain-v1` / `sv-dr-msg-v1`). Wire format is DIS-specific — no interop claim with libsignal. |
| **Derived (not random) GCM nonce** in `messaging` | Sound, and stronger here | The nonce is expanded from the message key alongside the AES key. Each message key is used exactly once by construction, so the nonce is unique by construction — strictly better than a random 96-bit IV, which carries a birthday bound. Does not apply to `aead`, which owns no such uniqueness guarantee and therefore draws a fresh random IV. |
| **Full header bound as AAD** | Good | `sv-dr-msg-v1‖0x00‖AD‖0x00‖canonical({v,dh,pn,n})`. The header is canonicalised from a fixed field order in DIS source, not from the peer's JSON key order, so a reordered header cannot produce a differing AAD. |
| **SecureBuffer** wiping | Best-effort | `fill(0)` + FinalizationRegistry fallback; cannot defeat GC/string immutability (residual risk R-1). |

## Compliance with the mandated crypto rules

| Rule | Status |
| --- | --- |
| Audited libraries only, no invented crypto | ✔ `hash-wasm`, WebCrypto, `@noble/post-quantum` |
| AEAD | ✔ AES-256-GCM everywhere |
| Unique nonces | ✔ `aead`/`vault`/`file`: fresh random IV per call (tested). `messaging`: nonce derived from the single-use message key, unique by construction |
| Format versioning | ✔ prefixed envelopes, fail-closed |
| Associated data | ✔ entry id / attachment context / chunk index |
| Strong KDF | ✔ Argon2id, versioned params |
| Key separation | ✔ KEK ≠ content key ≠ file key (HKDF info) |
| Key wrapping | ✔ `usk-wrap-v2` content-key wrapping |
| Secure randomness | ✔ WebCrypto CSPRNG, never `Math.random` |
| Negative tests | ✔ wrong key, tampered, AAD mismatch, downgrade; ratchet: forged ciphertext/header/counter, off-curve key, replay, state-intact-after-forgery |
| Test vectors | ◐ internal golden vectors for KDF/AEAD/vault/UserKey/PQ are present; **external vectors for Argon2id (RFC 9106), AES-GCM (NIST CAVP), HKDF (RFC 5869) and ML-KEM (NIST ACVP) are still missing**. |
| Documented migrations | ✔ this doc + migration-plan.md |
| No static salts | ✔ per-account random salt; HKDF zero-salt justified above |
| No password-as-key | ✔ always via Argon2id |
| No unauthenticated CBC | ✔ GCM only |
| No global mutable crypto state | ◐ one explicit provider seam (`setCryptoProvider`) is global by design; any in-process code can replace it. |
| No secrets in logs / no debug bypass / no hidden fallback | ✔ typed secret-free errors; legacy read only via explicit migration API |

## Findings / recommendations

- **F-1 (must, phase 1):** capture byte-exact golden vectors from production and
  add cross-implementation decrypt tests before any app cutover (RK-1).
- **F-2 (should):** add property-based and fuzz tests for the envelope/manifest
  parsers; add large-file streaming benchmarks.
- **F-3 (consider):** optional length-hiding padding as a future format version
  if metadata-size leakage (R-2) becomes in-scope.
- **F-4 (verify):** confirm browser and Tauri use identical flows; no Tauri-only
  crypto in shared logic (per testing-runtime.md).
- **F-5 (should, `messaging`):** a persisted ratchet state contains live chain
  keys and an extractable private key. Applications must store it encrypted
  under the user key, not in the clear — DIS cannot enforce this, so it belongs
  in the consuming app's review checklist (R-5).
- **F-6 (consider, `messaging`):** the ratchet currently has no bound on how
  long a session may run without a DH ratchet step. If an application only ever
  sends in one direction, post-compromise security never kicks in. Consider an
  app-level policy that forces a round trip periodically.

## Not verified

- Real-world zero-knowledge end-to-end (depends on app transport, not DIS).
- Prevalence of legacy no-AAD payloads in production.
- Correctness of nonce handling in app code outside the extracted modules.
