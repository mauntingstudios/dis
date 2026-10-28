# Risk Analysis & Refactor Prioritisation

Risk = likelihood × impact of the **extraction** going wrong (data loss,
incompatibility, security regression). Used to order the refactor.

## Risk register

| ID | Risk | Likelihood | Impact | Priority | Mitigation |
| --- | --- | --- | --- | --- | --- |
| RK-1 | Byte-format drift between DIS and existing data → existing vaults undecryptable | Med | Critical | **P0** | Freeze format constants; golden test vectors captured from production; cross-impl decrypt test before cutover |
| RK-2 | Legacy no-AAD payloads silently fail after cutover | Med | High | **P0** | Explicit migration API + telemetry of legacy prevalence before removing fallback |
| RK-3 | KDF parameter mismatch → wrong key derived | Low | Critical | **P0** | Immutable versioned `KDF_PARAMS`, determinism tests |
| RK-4 | Premium path-alias (`../singravault/src`) replaced incorrectly → Premium can't resolve crypto | High | High | **P1** | Replace alias with `@dis/shield` dep; build must fail without it |
| RK-5 | Apps retain shadow crypto copies → drift returns | Med | High | **P1** | Delete app crypto modules; lint rule banning raw `crypto.subtle` outside adapter |
| RK-6 | PQ hybrid extraction breaks sharing/emergency access | Med | High | **P1** | Port with hybrid version byte preserved; round-trip + migrate-to-hybrid tests |
| RK-7 | Memory-wiping regression | Low | Med | P2 | Keep `SecureBuffer`; secret-leak tests |
| RK-8 | Supply-chain compromise of new dep | Low | High | P2 | Pin versions, CI audit, encapsulate behind provider |
| RK-9 | License choice blocks legit commercial future | Low | Med | P2 | Dual-licensing path documented (see licensing.md) |
| RK-10 | Web vs Tauri crypto divergence | Med | Med | P2 | WebCrypto is common path; test both runtimes before release |

## Refactor order (by risk)

**Phase 0 — Foundation (this PR).** Implement + test pure primitives in DIS
(encoding, random, secure-memory, kdf, aead, vault-encryption, key-management,
file-encryption, integrity, format-versioning, migrations). Docs + license +
CI. No app changes. _Status: done in this PR._

**Phase 1 — Compatibility proof.** Capture golden vectors from production
Vault/Premium (one each: vault item, wrapped user key, attachment manifest +
chunk, hybrid blob). Add cross-impl tests asserting DIS decrypts them and the
app decrypts DIS output. Audit legacy no-AAD prevalence. _Gate before any app
change. Status: internal golden vectors for KDF/AEAD/vault/UserKey/PQ are in
`src/compat/`; the production attachment-manifest vector, the cross-impl app
test and the legacy prevalence audit are still open._

**Phase 2 — PQ hybrid + remaining modules.** Port `pqCryptoService` (ML-KEM-768
+ RSA) into `key-management` PQ submodule with version byte preserved.

**Phase 3 — Vault cutover.** Introduce app-local `crypto` adapter that re-exports
from `@dis/shield`; redirect ~35 call sites; delete `cryptoService.ts`,
`pqCryptoService.ts`, `secureBuffer.ts` internals. Add lint ban on raw
`crypto.subtle`. Make `@dis/shield` a hard dependency (build fails without it).

**Phase 4 — Premium cutover.** Replace `../singravault/src` path alias with
`@dis/shield`; route `fileAttachmentService` through `@dis/shield/file-encryption`.
Build/start must fail without DIS.

**Phase 5 — Verification.** Full test suites in both apps; dev-server + Tauri
runtime smoke tests of encrypt/decrypt, attachment up/download, password change,
sharing. Record runtime evidence.

## Hard gates (do not cross without sign-off)

- No removal of legacy fallback until production telemetry shows zero (or a
  migrated) legacy population.
- No app cutover until golden-vector cross-impl tests are green.
- No weakening of `device_key_required`, drift/quarantine, or integrity checks
  (forbidden by AGENTS.md).
