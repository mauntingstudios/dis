# Migrations

DIS provides a **migration framework** for evolving encrypted payload formats.
DIS does **not** ship any pre-registered migration steps — applications define
and register the migrations that match their own format history.

## Why a framework, not a registry

Migrations are inherently application-specific:

- The *subject* ("vault item", "user-key bundle", "attachment manifest") is
  chosen by the application.
- The *version detector* is a function that inspects a payload and returns its
  current version — it is shaped by the application's chosen format constants.
- The *step function* knows the application's old payload shape and how to
  rewrite it into the new one.

Hard-coding migrations into DIS would either bake in assumptions about one
specific app's format history, or explode into a swiss-army-knife that tries
to support every conceivable history. Neither is the right call.

## The pieces

```ts
import { MigrationRegistry, type Migration, type VersionDetector, type MigrationContext } from '@dis/shield';

// A single migration: transforms a payload from one version to the next.
interface Migration {
  subject: string;                  // e.g. 'vault item'
  fromVersion: number | 'legacy';
  toVersion: number;
  migrate(payload: string, context: MigrationContext): Promise<string>;
}

// Detects the current version of a payload. Returns 'legacy' for un-versioned payloads.
type VersionDetector = (payload: string) => number | 'legacy';

// Context passed to every step. The application owns key material and binding ids.
interface MigrationContext {
  key: CryptoKey;
  bindingId?: string;               // e.g. vault-item id, for AAD-bound formats
}

// The registry enforces (subject, fromVersion) uniqueness and runs steps in order.
const registry = new MigrationRegistry()
  .register(legacyNoAadToV1)
  .register(v1ToV2);
```

## End-to-end usage

```ts
import { MigrationRegistry, type VersionDetector } from '@dis/shield';

const detectVaultItemVersion: VersionDetector = (payload) => {
  if (payload.startsWith('sv-vault-v2:')) return 2;
  if (payload.startsWith('sv-vault-v1:')) return 1;
  return 'legacy';
};

const upgraded = await registry.migrateToLatest(
  'vault item',                     // subject
  storedCiphertext,                 // the persisted payload
  detectVaultItemVersion,           // how to read its current version
  { key: userKey, bindingId: entryId },
);
```

The registry walks `legacy → 1 → 2 → …` until a step is missing, then returns
the most recent migrated payload. Cycles are detected and throw
`DisError('INVALID_ARGUMENT', …)`.

## What a typical step looks like

```ts
// Re-wrap a legacy no-AAD vault item as sv-vault-v2 with AAD binding.
const legacyNoAadToV2: Migration = {
  subject: 'vault item',
  fromVersion: 'legacy',
  toVersion: 2,
  async migrate(payload, { key, bindingId }) {
    // Use the explicit migration helper — never re-encrypt on the runtime path.
    const { data } = await decryptVaultEntryForMigration(payload, key, bindingId!);
    return encryptVaultEntry(data, key, bindingId!);
  },
};
```

## Rules of thumb

- **One step, one version bump.** If you need `legacy → 1 → 2`, register two
  migrations; the registry chains them.
- **Steps must be idempotent on their output.** Re-running a step on its own
  output must not corrupt the payload. This is required for the cycle-guard
  to work and for safe retries.
- **Steps are pure with respect to key material.** A step may *use* `context.key`
  but must not mutate it. DIS wipes its own allocations; you own yours.
- **Don't put security decisions in the detector.** The detector is a parser
  (looks at a prefix, parses a header), not a verifier. Authenticate at the
  read boundary, not during migration.
- **For new applications, start with no migrations.** Only register steps when
  you have a concrete format change to ship.

## When to NOT use this framework

- **One-off format fixes during development** — just write a one-time script
  that calls the migration helpers and updates the database. The framework is
  for migrations that may re-run on user data after a deploy.
- **Schema migrations of plain (non-encrypted) columns** — that's a database
  concern, not a crypto one. Use your database's native migration tooling.
