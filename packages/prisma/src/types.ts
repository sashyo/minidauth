/** A minimal shape for the `Prisma` object your generated client exports. */
export interface PrismaLike {
  defineExtension: (ext: any) => any;
}

export interface MinidauthSealConfig {
  /**
   * The `Prisma` value from your own generated client, e.g. `import { Prisma } from "@prisma/client"`
   * (or from your custom output path). The extension is defined against the client it wraps.
   */
  Prisma: PrismaLike;

  /**
   * String-field mode. camelCase model name -> the scalar string fields to seal on that model. Each
   * sealed value is stored as `ms1:<ciphertext>`. Seal the personal fields the database never sorts,
   * filters, or searches on; leave identity and lookup keys (an indexed email, an opaque routing
   * token) out, so they stay queryable.
   *
   * e.g. `{ recipient: ["name"], documentMeta: ["subject", "message"] }`
   */
  sealed?: Record<string, string[]>;

  /**
   * JSON-column mode. camelCase model name -> the JSON columns to seal on that model. Each column is a
   * `Record<key, value>`; every entry's value is sealed and the column is stored as
   * `{ _ms: 1, fields: { key: ciphertext } }`, opened back to the original object on read. Use this
   * for a payload column (survey answers, an attributes bag) rather than a fixed scalar field.
   *
   * e.g. `{ response: ["data", "contactAttributes"] }`
   */
  json?: Record<string, string[]>;

  /**
   * Optional. model -> { relationKey: relatedModel }, the relations to descend into so a nested write
   * and an included read both reach a child's sealed fields. String mode only; JSON bags are
   * self-contained. Directional (no back-references) so descent always terminates.
   *
   * e.g. `{ envelope: { recipients: "recipient", fields: "field" } }`
   */
  relations?: Record<string, Record<string, string>>;

  /**
   * Optional. When false (the default), a read with no reader identity in context leaves the field
   * sealed. Set true when the sidecar itself holds the reading role and you are not threading a
   * per-request reader (opens then go out without a bearer). String-mode integrations that gate reads
   * per user should leave this false.
   */
  openWithoutReader?: boolean;

  /**
   * Optional. Override how the sidecar base URL is resolved. Default: `() => process.env.MINIDAUTH_SEAL_URL`.
   */
  sealUrl?: () => string | undefined;

  /**
   * Optional. Override the on/off predicate. Default: `() => Boolean(sealUrl())`.
   */
  enabled?: () => boolean;
}

export interface MinidauthSeal {
  /** Pass to `prisma.$extends(...)`. Append it last so it is the outermost layer. */
  extension: any;
  /**
   * Open sealed fields on records that bypassed the Prisma client (raw SQL / query builders). A no-op
   * when sealing is off. Same reader gate, same batching, same fail-safe as a Prisma read.
   */
  openSealedRecords: (model: string, records: any) => Promise<void>;
}
