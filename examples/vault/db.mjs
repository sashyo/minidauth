// Supabase side of Vault. The secret key bypasses row-level security — which is exactly what a
// leak of it would give an attacker — so every sensitive column it touches is stored as ciphertext.
import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPABASE_URL;
const ANON = process.env.SUPABASE_ANON_KEY;            // safe in the browser
const SECRET = process.env.SUPABASE_SERVICE_ROLE_KEY;  // never in the browser

export const publicConfig = () => ({ url: URL, anonKey: ANON });
export function missingConfig() {
  return Object.entries({ SUPABASE_URL: URL, SUPABASE_ANON_KEY: ANON, SUPABASE_SERVICE_ROLE_KEY: SECRET })
    .filter(([, v]) => !v).map(([k]) => k);
}
const admin = () => createClient(URL, SECRET, { auth: { persistSession: false } });
const must = ({ data, error }) => { if (error) throw new Error(error.message); return data; };

/** Who this access token belongs to, as Supabase itself answers it. */
export async function userFor(accessToken) {
  if (!accessToken || !URL) return null;
  const { data, error } = await createClient(URL, ANON).auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return { id: data.user.id, email: data.user.email };
}

/** Records: name is clear (for the list), every sensitive field is a ciphertext blob under `ct`. */
export async function records() {
  const rows = must(await admin().from("vault_records").select("*").order("created_at", { ascending: false }));
  return rows.map((r) => ({ id: r.id, name: r.name, ref: r.ref, ct: r.ciphertext ?? {}, created: r.created_at?.slice(0, 10) }));
}
export async function addRecord({ name, ref, ct, by }) {
  const row = must(await admin().from("vault_records").insert({ name, ref, ciphertext: ct, created_by: by }).select().single());
  return { id: row.id, name: row.name, ref: row.ref, ct: row.ciphertext ?? {}, created: row.created_at?.slice(0, 10) };
}

/** A signed release. The signature is the network's, over the instruction; we store what it answered. */
export async function recordRelease({ record, amount, signature, by }) {
  if (!signature) throw new Error("a release must carry the network's signature");
  return must(await admin().from("vault_releases").insert({ record_id: record, amount, signature, requested_by: by, status: "signed" }).select().single());
}
