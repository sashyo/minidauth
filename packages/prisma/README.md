# minidauth-prisma

Seal selected Prisma fields with [minidauth](https://github.com/sashyo/minidauth) before they reach Postgres, and open them again on read for a user a quorum granted the role. It is one Prisma client extension, driven by a field map you supply. Your app and your database only ever hold ciphertext; the key lives as threshold shares across the Tide ORK cohort and is never assembled in your process.

Off unless configured. With `MINIDAUTH_SEAL_URL` unset, every path is a no-op and your app behaves exactly like it did before.

## Why this exists

Field-level encryption in a Prisma app usually means one of two bad options: encrypt by hand at every call site, or fork the app to slip a seal step into its shared client. This packages the seal step as a normal Prisma extension so you add one line to your client and a small config, instead of carrying a fork.

The engine is the same one running in the Cal.com and Documenso minidauth forks. This package is that code with the per-app field map lifted out into config.

## Install

```sh
npm i minidauth-prisma
```

Needs Node 18+ (it uses `fetch`, `node:async_hooks`, and Ed25519 from `node:crypto`). You also need the minidauth-seal sidecar running and `MINIDAUTH_SEAL_URL` pointing at it. See the [minidauth docs](https://github.com/sashyo/minidauth) for the sidecar.

## Use

Two steps: wrap your Prisma client, and tell each request who is reading.

### 1. Seal on write, open on read

```ts
import { PrismaClient, Prisma } from "@prisma/client";
import { createMinidauthSeal } from "minidauth-prisma";

const { extension } = createMinidauthSeal({
  Prisma, // the Prisma value from YOUR generated client
  sealed: {
    // camelCase model -> the string fields to seal
    attendee: ["name", "phoneNumber"],
    booking: ["title", "description"],
  },
  relations: {
    // descend into these so nested writes and included reads reach a child's sealed fields
    booking: { attendees: "attendee" },
  },
});

// Append it last so it is the outermost layer.
export const prisma = new PrismaClient().$extends(extension);
```

Pass `Prisma` from your own generated client, whether that is `@prisma/client` or a custom output path. The extension has to be defined against the client it wraps.

Leave identity and lookup keys out of `sealed`. A sealed column holds ciphertext, so the database cannot sort, filter, or search on it. Keep the columns you query on (an indexed email, an opaque routing token) in the clear.

### 2. Tell each request who is reading

The sidecar decrypts only on behalf of a named user, and only if minidauth's quorum grant says that user holds the reading role. Prisma extensions get no request context, so you thread the reader yourself: wrap each request's work so any sealed read inside it opens as that user.

```ts
import { withMinidauthReader } from "minidauth-prisma";

// in your auth middleware, tRPC context, route handler, etc.
return withMinidauthReader(session.user.id, () => next());
```

Outside a `withMinidauthReader` scope there is no reader, so reads stay sealed. Ciphertext is the safe default; there is no standing reader for an unauthenticated caller to borrow.

To sign the reader token with a key only your app holds, set `MINIDAUTH_SEAL_SIGNING_KEY_FILE` to an Ed25519 private key PEM (minidauth verifies it with the public half). For a quick start you can instead set `MINIDAUTH_SEAL_TOKEN_SECRET` to an HS256 secret, but the shared secret can forge any granted user, so use the key file in real deployments.

### Reads that bypass Prisma

If some of your reads use raw SQL or a query builder, they skip the extension's hooks and their sealed columns come back as ciphertext. Open those results before returning them:

```ts
const { extension, openSealedRecords } = createMinidauthSeal({ /* ... */ });

const rows = await prisma.$queryRaw`SELECT ... FROM booking ...`;
await openSealedRecords("booking", rows); // same reader gate, same batching
```

## What it does

- **Seals** on `create`, `update`, `upsert`, `createMany`, `updateMany`, descending into nested `create` / `createMany.data` / `connectOrCreate.create` so a parent's children seal with it.
- **Opens** on `findUnique(OrThrow)`, `findFirst(OrThrow)`, `findMany`, and on the rows returned by writes, descending into included relations.
- **Batches**: every sealed field in one operation, or a whole page of results, opens in a single cohort round trip, not one per field.
- **Fails closed on write**: if the sidecar is unreachable, the write throws rather than storing plaintext.
- **Fails safe on read**: no reader in context, an ungranted reader, or a sidecar that is down all leave the field sealed rather than crashing the read.

## Config

| Field | Meaning |
| --- | --- |
| `Prisma` | The `Prisma` value from your generated client. Required. |
| `sealed` | `{ model: [field, ...] }`, camelCase model name to the scalar string fields to seal. |
| `relations` | Optional. `{ model: { relationKey: relatedModel } }`, the relations to descend into. Directional; the descent walks whatever objects a write or read actually contains, so a finite object graph always terminates. |

Env vars, all read at runtime:

| Var | Meaning |
| --- | --- |
| `MINIDAUTH_SEAL_URL` | The sidecar base URL. Unset means sealing is off and everything is a no-op. |
| `MINIDAUTH_SEAL_SIGNING_KEY_FILE` | Path to an Ed25519 private key PEM used to sign the reader token. Preferred. |
| `MINIDAUTH_SEAL_SIGNING_KEY` | The key PEM inline, as an alternative to the file. |
| `MINIDAUTH_SEAL_TOKEN_SECRET` | HS256 fallback secret for the reader token. Quick start only. |

## Scope and limits

This is a proof-of-concept sealing scheme: it sends each field value to the sidecar to seal and open. A production build would protect one per-record data key with the cohort and AES the payload under it locally (envelope encryption), one cohort op per record. The queryability limit stands either way: a sealed column is opaque to the database.

It covers two shapes: **string columns** stored as `ms1:<ciphertext>` (`sealed`), and a **whole JSON column** stored as a `{ _ms: 1, fields }` bag (`json`). A column the database has to sort, filter, or search on cannot be sealed either way.

## Reference adopters

These forks run this package against the live Tide network. Each is config plus one `.$extends(...)` line, no forked crypto:

| App | What it seals | Mode |
| --- | --- | --- |
| [Cal.com](https://github.com/sashyo/cal.diy) | attendee name and phone, booking title and description | `sealed` |
| [Documenso](https://github.com/sashyo/documenso) | document title, recipient name, email subject/message, signatures, field text | `sealed` |
| [Formbricks](https://github.com/sashyo/formbricks) | survey response `data` and `contactAttributes` | `json` |

## License

MIT
