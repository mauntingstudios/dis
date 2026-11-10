# DIS Architecture

## Goal

DIS is the single cryptographic security layer for Singra Vault, Singra
Premium, and future projects. Applications must contain **no direct crypto
logic** and consume DIS only through stable, versioned public APIs. Internal
changes to KDFs, ciphers, key hierarchies, or data formats must, wherever
possible, not force changes in consuming applications.

## Design principles

1. **No invented cryptography.** Only audited primitives (Argon2id via
   `hash-wasm`, AES-256-GCM / HKDF / SHA-256 via WebCrypto, ML-KEM-768 via
   `@noble/post-quantum`).
2. **Framework independence.** No React, no DOM-beyond-WebCrypto, no database,
   no UI, no app data models. Runs in browser, Node ≥ 20, and (future) mobile
   JS runtimes.
3. **Versioned formats.** Every persisted ciphertext is self-describing via a
   stable prefix. Unknown in-family versions fail closed.
4. **Key separation.** Distinct keys per purpose (KEK vs content key vs file
   key), derived/ wrapped, never reused across purposes.
5. **Pluggable providers.** A `CryptoProvider` seam allows substituting the
   WebCrypto implementation (tests, hardware backends) without touching call
   sites.
6. **Memory hygiene.** Key material flows through `SecureBuffer` / wiped
   `Uint8Array`s; no secrets in immutable strings where avoidable.
7. **Honest errors.** A typed error hierarchy; no secrets in messages; AEAD
   failures are indistinguishable (no padding/AAD oracle).

## Packaging decision: single package, modular entry points

The requirement lists ~11 example modules (`dis-core`, `dis-kdf`, …). We
evaluated three layouts:

| Option | Pros | Cons |
| --- | --- | --- |
| **One package, many subpath exports** (chosen) | One version to reason about; trivial cross-module refactors; tree-shakeable; minimal release/CI overhead; easy for two tightly-coupled apps to adopt | Cannot version a single module independently |
| Workspaces monorepo, N published packages | Independent versioning | High overhead (build ordering, inter-dep version churn), premature for v0, harder to keep green |
| One repo, one flat module | Simplest | Violates "no utility dumping ground"; poor boundaries |

**Decision:** ship `@dis/shield` as **one semantically-versioned package with
per-module subpath exports** (`@dis/shield/kdf`, `/aead`, `/vault-encryption`,
…). This satisfies modularity, tree-shaking, and "not everything in one utility
module" while keeping the foundation maintainable. The directory boundaries are
deliberately clean so that, if independent versioning is later needed, modules
can be promoted to workspace packages with no API change.

## Module boundaries

```
core ──────────────┐  (errors, encoding, constants, provider)  no deps
random ─────────────┤  uses core.provider
secure-memory ──────┤  uses core
kdf ────────────────┤  uses core + hash-wasm (Argon2id) + WebCrypto HKDF
aead ───────────────┤  uses core (AES-256-GCM)
format-versioning ──┤  uses core
integrity ──────────┤  uses core (SHA-256)
vault-encryption ───┤  uses aead + format-versioning
key-management ─────┤  uses aead + kdf + random (wrap/unwrap/rotate)
file-encryption ────┤  uses aead + kdf + random + integrity (chunked)
messaging ──────────┤  uses aead + kdf + secure-memory + format-versioning
                    │  (Double Ratchet; pure state machine, no storage)
migrations ─────────┘  framework over the above
index (SDK facade) ─── stable public surface re-exporting the above
```

Dependencies only point "downward" toward `core`. There are no cycles.

## What DIS does NOT contain

- No UI, routing, React, or component code.
- No database / Supabase / storage client. File encryption is storage-agnostic
  (caller supplies chunk read/write callbacks).
- No app data models (vault item schema, collections, billing, admin). A vault
  entry is an opaque `Record<string, unknown>`.
- No network, telemetry, analytics, or logging of secrets.

## Provider abstraction

`getCryptoProvider()` resolves `globalThis.crypto` by default and can be
overridden via `setCryptoProvider()`. This is the only place DIS touches a
global, keeping the rest of the code testable and portable.

## Compatibility contract

DIS reproduces Singra's on-disk formats exactly (envelope prefixes, IV‖CT‖tag
layout, AAD strings, HKDF `info` labels, KDF parameters). This is what allows
the applications to adopt DIS without re-encrypting existing data. These format
constants are frozen; evolving them means **adding a version**, never editing
one. See `crypto-dependency-map.md` and `migration-plan.md`.

## Higher-level application integration

Consumer applications (such as Maunting Service Manager) compose DIS primitives into application-level security workflows:
- **Smartcard & Wallet Logic:** Cross-device zero-knowledge identity, blind bucket seed derivation, and ephemeral E2EE relays. See [smartcard-architecture.md](./smartcard-architecture.md) (German version: [smartcard-architecture.de.md](./smartcard-architecture.de.md)).
