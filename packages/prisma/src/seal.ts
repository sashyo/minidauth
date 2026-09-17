/**
 * minidauth field sealing as a Prisma client extension, config-driven.
 *
 * Seals the fields you name with minidauth before they reach Postgres, and opens them again on the way
 * out. The crypto runs in the minidauth-seal sidecar, which talks to minidauth and the Tide ORK
 * cohort, so this app and Postgres only ever hold ciphertext. The vendor key lives as threshold shares
 * across the ORK network and is never assembled here, so a stolen database or a leaked backup is
 * unreadable, and a quorum (not this app) decides whether records can be read at all: the reader must
 * hold a quorum-granted role, or `open` returns nothing and the field stays sealed.
 *
 * Two modes, usable together:
 *   - string mode (`sealed`): scalar string columns, stored as "ms1:<ciphertext>", with relation
 *     descent for nested writes and included reads.
 *   - JSON mode (`json`): a whole JSON column (a Record<key, value>), stored as { _ms: 1, fields }.
 *
 * Off by default. Set MINIDAUTH_SEAL_URL to point at the sidecar to turn it on; unset, every path
 * below is a no-op and the app behaves exactly like upstream.
 *
 * It batches: every sealed field in one operation (a parent plus its nested children, or a whole page
 * of results) opens in a single cohort fan-out, not one round trip per field. The remaining limit is
 * queryability. Sealed columns hold ciphertext, so the database cannot sort, filter, or search on
 * them, which is why you should leave identity and lookup keys in the clear.
 */
import { currentReaderToken } from "./reader";
import type { MinidauthSeal, MinidauthSealConfig } from "./types";

const MARKER = "ms1:"; // a sealed string column is "ms1:<ciphertextB64>"
const isSealedString = (v: unknown): v is string => typeof v === "string" && v.startsWith(MARKER);

// A sealed JSON column: the original Record with every value replaced by ciphertext, wrapped so a read
// can tell a sealed bag from a plain object.
interface SealedBag {
  _ms: 1;
  fields: Record<string, string>;
}
const isSealedBag = (v: unknown): v is SealedBag =>
  !!v && typeof v === "object" && (v as SealedBag)._ms === 1 && typeof (v as SealedBag).fields === "object";

// A leaf is one string value we can read and write in place, so the same code seals and opens it.
type Leaf = { get: () => unknown; set: (v: unknown) => void };
const leaf = (obj: any, key: string): Leaf => ({ get: () => obj[key], set: (v) => (obj[key] = v) });

/**
 * Build the minidauth sealing layer for your Prisma client from a field map. See MinidauthSealConfig
 * for the options. Returns the `.$extends(...)` argument and an `openSealedRecords` helper for results
 * that bypass the Prisma client (raw SQL / query builders), which the extension's `query` hooks never
 * see.
 */
export function createMinidauthSeal(config: MinidauthSealConfig): MinidauthSeal {
  const { Prisma, sealed = {}, json = {}, relations = {} } = config;
  const openWithoutReader = config.openWithoutReader ?? false;
  const sealUrl = config.sealUrl ?? (() => process.env.MINIDAUTH_SEAL_URL);
  const enabled = config.enabled ?? (() => Boolean(sealUrl()));

  async function sidecar(path: string, body: unknown, bearer?: string): Promise<any> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (bearer) {
      headers["Authorization"] = `Bearer ${bearer}`; // the reader's delegation token, on /open
    }
    const r = await fetch(sealUrl() + path, { method: "POST", headers, body: JSON.stringify(body) });
    const text = await r.text();
    if (!r.ok) {
      throw new Error(`minidauth-seal ${path} -> ${r.status} ${text}`);
    }
    return text ? JSON.parse(text) : {};
  }

  // The reader gate, shared by both modes. Returns whether an open may proceed, and the bearer to send
  // (undefined when the sidecar itself holds the reading identity, see openWithoutReader).
  let openWarned = false;
  function readerGate(): { allowed: boolean; token?: string } {
    const token = currentReaderToken();
    if (!token && !openWithoutReader) {
      if (!openWarned) {
        openWarned = true;
        console.warn("[minidauth-seal] no reader identity in context; leaving records sealed");
      }
      return { allowed: false };
    }
    return { allowed: true, token };
  }

  // ---- string mode ---------------------------------------------------------------------------------

  // Write side: collect the plaintext leaves in a create/update `data` shape, descending into nested
  // creates (create, createMany.data, connectOrCreate.create) so a parent's children seal with it.
  function collectWriteLeaves(model: string, data: any, out: Leaf[]): void {
    if (!data || typeof data !== "object") {
      return;
    }
    for (const f of sealed[model] || []) {
      // Collect every non-empty string, even one that already looks sealed. We do NOT skip an "ms1:"
      // value: a client can forge the prefix, and only the cohort can tell a real seal from a forgery
      // (via the VVK signature), so the sidecar seals everything and a forged prefix never lets
      // plaintext reach a sealed column. Callers pass plaintext here (reads open to plaintext), so this
      // does not double-seal in normal use.
      const v = data[f];
      if (typeof v === "string" && v.length > 0) {
        out.push(leaf(data, f));
      }
    }
    for (const [key, childModel] of Object.entries(relations[model] || {})) {
      const nested = data[key];
      if (!nested || typeof nested !== "object") {
        continue;
      }
      const creates = ([] as any[])
        .concat(nested.create ?? [])
        .concat(nested.createMany?.data ?? [])
        .concat(
          (Array.isArray(nested.connectOrCreate) ? nested.connectOrCreate : [nested.connectOrCreate])
            .map((c: any) => c?.create)
            .filter(Boolean)
        );
      for (const c of creates) {
        collectWriteLeaves(childModel, c, out);
      }
    }
  }

  // Read side: collect the sealed leaves in a returned record, descending into included relations.
  function collectReadLeaves(model: string, node: any, out: Leaf[]): void {
    if (!node || typeof node !== "object") {
      return;
    }
    for (const f of sealed[model] || []) {
      if (isSealedString(node[f])) {
        out.push(leaf(node, f));
      }
    }
    for (const [key, childModel] of Object.entries(relations[model] || {})) {
      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach((c) => collectReadLeaves(childModel, c, out));
      } else if (child && typeof child === "object") {
        collectReadLeaves(childModel, child, out);
      }
    }
  }

  // Seal fails closed: if the sidecar is unreachable, the write throws rather than storing plaintext.
  async function sealLeaves(leaves: Leaf[]): Promise<void> {
    if (leaves.length === 0) {
      return;
    }
    const fields: Record<string, string> = {};
    leaves.forEach((l, i) => (fields[String(i)] = l.get() as string));
    // The sidecar returns marker-included values (it decides what is real ciphertext), so store them
    // as-is; prepending the marker here would double it.
    const { sealed: out } = await sidecar("/seal", { fields });
    leaves.forEach((l, i) => l.set((out as Record<string, string>)[String(i)]));
  }

  // Open is best-effort and gated on the reader. No reader in context (unless openWithoutReader), an
  // ungranted reader, or a sidecar that is down all leave the field sealed rather than crashing the
  // read. Ciphertext is the safe failure.
  async function openLeaves(leaves: Leaf[]): Promise<void> {
    if (leaves.length === 0) {
      return;
    }
    const { allowed, token } = readerGate();
    if (!allowed) {
      return;
    }
    try {
      const fields: Record<string, string> = {};
      leaves.forEach((l, i) => (fields[String(i)] = (l.get() as string).slice(MARKER.length)));
      const { fields: opened } = await sidecar("/open", { fields }, token); // one cohort fan-out
      leaves.forEach((l, i) => l.set((opened as Record<string, string>)[String(i)]));
    } catch (e) {
      if (!openWarned) {
        openWarned = true;
        console.warn("[minidauth-seal] leaving records sealed:", (e as Error).message);
      }
    }
  }

  // ---- JSON mode -----------------------------------------------------------------------------------

  // Turn one { key: value } bag into a sealed bag of ciphertext, JSON-serialising each value so
  // numbers, arrays and objects survive the round trip. Idempotent: an already-sealed bag is left as is.
  async function sealBag(bag: unknown): Promise<unknown> {
    if (!bag || typeof bag !== "object" || isSealedBag(bag)) {
      return bag;
    }
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(bag as Record<string, unknown>)) {
      if (v !== undefined && v !== null) {
        fields[k] = JSON.stringify(v);
      }
    }
    if (Object.keys(fields).length === 0) {
      return bag;
    }
    const { sealed: out } = await sidecar("/seal", { fields });
    return { _ms: 1, fields: out } as SealedBag;
  }

  async function openBag(bag: unknown): Promise<unknown> {
    if (!isSealedBag(bag)) {
      return bag;
    }
    const { allowed, token } = readerGate();
    if (!allowed) {
      return bag;
    }
    const { fields } = await sidecar("/open", { fields: bag.fields }, token);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(fields as Record<string, string>)) {
      out[k] = JSON.parse(v);
    }
    return out;
  }

  // ---- shared write/read across both modes ---------------------------------------------------------

  async function sealWrite(model: string, data: any): Promise<any> {
    if (!data || typeof data !== "object") {
      return data;
    }
    const leaves: Leaf[] = [];
    collectWriteLeaves(model, data, leaves);
    await sealLeaves(leaves);
    for (const f of json[model] || []) {
      if (f in data) {
        data[f] = await sealBag(data[f]);
      }
    }
    return data;
  }

  async function openRead(model: string, result: any): Promise<void> {
    const leaves: Leaf[] = [];
    if (Array.isArray(result)) {
      result.forEach((r) => collectReadLeaves(model, r, leaves));
    } else {
      collectReadLeaves(model, result, leaves);
    }
    await openLeaves(leaves);

    const jsonFields = json[model] || [];
    if (jsonFields.length > 0) {
      const rows = Array.isArray(result) ? result : [result];
      for (const row of rows) {
        if (!row || typeof row !== "object") {
          continue;
        }
        for (const f of jsonFields) {
          if (isSealedBag(row[f])) {
            try {
              row[f] = await openBag(row[f]);
            } catch (e) {
              if (!openWarned) {
                openWarned = true;
                console.warn("[minidauth-seal] leaving records sealed:", (e as Error).message);
              }
            }
          }
        }
      }
    }
  }

  // Open sealed fields on records that did NOT come through the client extension. Apps that build some
  // reads with raw SQL or a query builder bypass the `query` hooks below, so their sealed columns
  // arrive as ciphertext. Call this on such results before returning them. Same reader gate, same
  // one-fan-out batching, same fail-safe. A no-op when sealing is off.
  async function openSealedRecords(model: string, records: any): Promise<void> {
    if (!enabled() || !records) {
      return;
    }
    await openRead(model, records);
  }

  const query: Record<string, any> = {};
  const models = new Set([...Object.keys(sealed), ...Object.keys(json)]);
  for (const model of models) {
    query[model] = {
      async create({ args, query }: any) {
        if (!enabled()) {
          return query(args);
        }
        args.data = await sealWrite(model, args.data);
        const res = await query(args);
        await openRead(model, res);
        return res;
      },
      async update({ args, query }: any) {
        if (!enabled()) {
          return query(args);
        }
        args.data = await sealWrite(model, args.data);
        const res = await query(args);
        await openRead(model, res);
        return res;
      },
      async upsert({ args, query }: any) {
        if (!enabled()) {
          return query(args);
        }
        args.create = await sealWrite(model, args.create);
        args.update = await sealWrite(model, args.update);
        const res = await query(args);
        await openRead(model, res);
        return res;
      },
      async createMany({ args, query }: any) {
        if (!enabled()) {
          return query(args);
        }
        if (Array.isArray(args.data)) {
          args.data = await Promise.all(args.data.map((d: any) => sealWrite(model, d)));
        } else {
          args.data = await sealWrite(model, args.data);
        }
        return query(args); // createMany returns a count, nothing to open
      },
      async updateMany({ args, query }: any) {
        if (!enabled()) {
          return query(args);
        }
        args.data = await sealWrite(model, args.data);
        return query(args);
      },
      async findUnique({ args, query }: any) {
        const res = await query(args);
        if (enabled()) {
          await openRead(model, res);
        }
        return res;
      },
      async findUniqueOrThrow({ args, query }: any) {
        const res = await query(args);
        if (enabled()) {
          await openRead(model, res);
        }
        return res;
      },
      async findFirst({ args, query }: any) {
        const res = await query(args);
        if (enabled()) {
          await openRead(model, res);
        }
        return res;
      },
      async findFirstOrThrow({ args, query }: any) {
        const res = await query(args);
        if (enabled()) {
          await openRead(model, res);
        }
        return res;
      },
      async findMany({ args, query }: any) {
        const res = await query(args);
        if (enabled()) {
          await openRead(model, res);
        }
        return res;
      },
    };
  }

  // The query object is built dynamically from the field maps, so its keys are not statically known to
  // Prisma's generated types; the per-model handler shapes are correct at runtime. Cast to the
  // expected argument type.
  const extension = Prisma.defineExtension({ name: "minidauth-seal", query } as any);

  return { extension, openSealedRecords };
}
