# Contributing to DIS

DIS — Defensive Integration Shield is the central cryptographic layer for Singra
Vault, Singra Premium, and future projects. Crypto code carries unusual risk, so
contributions follow strict rules.

## Contributor License Agreement (CLA)

By submitting a contribution you agree that:

1. You have the right to submit the work.
2. You license your contribution under the project license
   ([PolyForm Noncommercial 1.0.0](LICENSE)), **and** you grant the maintainer a
   perpetual, irrevocable right to relicense your contribution, including under
   commercial terms.

This preserves the project's ability to offer commercial licenses. PRs cannot be
merged without CLA agreement.

## Hard rules (non-negotiable)

- **No invented cryptography.** Only audited primitives (`hash-wasm`, WebCrypto,
  `@noble/post-quantum`). New crypto dependencies require explicit review per the
  dependency policy.
- **AEAD only**, unique nonce per call, AAD where context matters, strong KDFs,
  key separation, key wrapping, secure randomness.
- **Never** static salts, password-as-key, unauthenticated CBC, global mutable
  crypto state, secrets in logs, debug bypasses, or hidden fallbacks.
- **Formats are append-only.** Never edit an existing versioned format; add a new
  version. Persisted-format constants are frozen.
- **Every change ships with tests** — including negative tests (wrong key,
  tampered data, AAD mismatch, downgrade) and, for formats, test vectors.

## Test conventions

Negative tests come first. A happy-path test proves that the logic works; the
negative tests prove that the system fails closed when it is attacked. Every
parser, envelope or format change needs at least: wrong type, wrong length,
wrong AAD, tampered ciphertext, and a downgrade or replay attempt.

- Tests live next to the code as `src/<module>/<name>.test.ts`.
- Group rejection cases as `describe('<module> — negative', ...)` and name them
  `it('rejects ...', ...)`.
- Use `it.each` for field-by-field tampering tables instead of copy-pasted
  blocks.
- Shared helpers live in `src/test/disTestUtils.ts` (`tamperBase64`,
  `withFixedProvider`).
- A fix's test must be red on the pre-fix code and green after it. Mention the
  red proof in the PR; a test that was already green does not prove the fix.

## Workflow

1. Branch from `main` (never commit to `main`/`master` directly).
2. `npm install`
3. Make the change with focused commits.
4. Run the full gate locally:
   ```bash
   npm run lint
   npm run typecheck
   npm test
   npm run build
   ```
5. Open a PR. CI must be green. Security-relevant changes need maintainer review.

## Definition of done

A change is done only when invariants are tested and runtime-critical paths are
exercised — a green typecheck or build alone is **not** sufficient. Unrun checks
must be stated honestly in the PR.
