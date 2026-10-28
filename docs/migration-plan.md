# Migration Plan

How the applications move from in-tree crypto to consuming `@dis/shield`
exclusively, without re-encrypting existing data and without weakening any
security control.

## Principles

- **No data re-encryption** is required: DIS reproduces existing formats
  byte-for-byte.
- **No format edits**, only additive versions.
- **No app cutover** until cross-implementation golden vectors pass.
- **No removal of legacy read paths** until production telemetry justifies it.

## Format compatibility matrix

| Format | Producer today | DIS reads | DIS writes | Notes |
| --- | --- | --- | --- | --- |
| `sv-vault-v2:` vault item (AAD=`sv-vault-v2:entryId`) | Vault | ✔ | ✔ | current write format |
| `sv-vault-v1:` vault item (AAD=entryId) | Vault (old) | ✔ | ✘ | read compatibility; still downgradeable |
| legacy no-AAD vault item | Vault (old) | migration API only | ✘ | upgraded to v2 on migration |
| `usk-wrap-v2:` user key | Vault | ✔ | ✔ | HKDF info `singra-vault-wrap-v1` |
| legacy unprefixed user key | Vault (old) | ✔ (read) | ✘ | re-wrapped to v2 on next rotation |
| `sv-file-manifest-v2:` object + HMAC | Premium | ✔ | ✔ | metadata and chunk list authenticated |
| `sv-file-manifest-v1:` + chunks | Premium | ✔ | ✘ | legacy, not truncation-protected |
| hybrid PQ blob (`VERSION_HYBRID_STANDARD_V2`) | Vault | phase 2 | phase 2 | layout preserved |

## Step-by-step

### Phase 1 — Compatibility proof (gate)
1. From a production-like Vault/Premium instance, export one sample of each
   format above (ciphertext only — never plaintext or keys).
2. Add `*.vectors.test.ts` in DIS: assert DIS decrypts each sample, and that the
   app decrypts DIS-produced output for the same inputs.
3. Instrument the apps to count legacy (no-AAD / unprefixed) payloads.
4. **Gate:** all vector tests green; legacy prevalence known.

### Phase 2 — PQ hybrid port
5. Port `pqCryptoService` into `@dis/shield/key-management` (PQ submodule),
   preserving the version byte and blob layout; add round-trip + `migrateToHybrid`
   tests.

### Phase 3 — Vault cutover
6. Add `@dis/shield` as a **hard dependency** of Vault.
7. Add app-local `src/services/crypto/index.ts` adapter that re-exports DIS
   symbols (keeps existing import sites stable initially).
8. Redirect ~35 call sites to the adapter / DIS facade.
9. Delete `cryptoService.ts`, `pqCryptoService.ts`, internal `secureBuffer.ts`.
10. Add ESLint rule banning `crypto.subtle` / `hash-wasm` / `@noble/post-quantum`
    imports outside the adapter.
11. **Verify:** `npm run lint && npm run typecheck && npm test`; dev server +
    Tauri smoke test (unlock, read/write item, password change).
12. **Build-fails-without-DIS:** confirm removing `@dis/shield` breaks build and
    start (no fallback).

### Phase 4 — Premium cutover
13. Replace the `../singravault/src` path alias (vitest/build config) with the
    `@dis/shield` dependency.
14. Route `fileAttachmentService` through `@dis/shield/file-encryption`
    (callbacks bridge to Supabase/Tauri storage).
15. Delete duplicated crypto; add the same lint ban.
16. **Verify:** Premium test suite + attachment upload/download/restore runtime
    test; confirm build/start fail without DIS.

### Phase 5 — Legacy retirement (later, optional)
17. Once telemetry shows zero legacy payloads (or all migrated), remove the
    no-AAD migration fallback in a **major** DIS release with a documented note.

## Rollback

Each phase is a separate PR. If a regression appears, revert the app PR; DIS
remains installed and inert. No data is mutated by installation alone.
