import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPABASE_URL;
const PUBLISHABLE = process.env.SUPABASE_ANON_KEY;       // safe in the browser
const SECRET = process.env.SUPABASE_SERVICE_ROLE_KEY;    // never in the browser

export const publicConfig = () => ({ url: URL, anonKey: PUBLISHABLE });

export function missingConfig() {
  return Object.entries({ SUPABASE_URL: URL, SUPABASE_ANON_KEY: PUBLISHABLE,
    SUPABASE_SERVICE_ROLE_KEY: SECRET })
    .filter(([, v]) => !v).map(([k]) => k);
}

/* The secret key bypasses row level security, which is what a server needs and exactly what an
 * attacker wants. Everything below uses it, so everything below is what a leak of it exposes. */
const admin = () => createClient(URL, SECRET, { auth: { persistSession: false } });

function must({ data, error }) {
  if (error) throw new Error(error.message);
  return data;
}

/** Who this access token belongs to, as Supabase itself answers it. */
export async function userFor(accessToken) {
  if (!accessToken) return null;
  const { data, error } = await createClient(URL, PUBLISHABLE).auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return {
    id: data.user.id,
    email: data.user.email,
    // app_metadata, because the user can write their own user_metadata.
    vuid: data.user.app_metadata?.tide_vuid ?? null,
  };
}

/* The Tide identity goes on the user. Roles do not: Supabase copies app_metadata into the tokens it
 * mints, and a role in a token this project can mint is a role this project can grant itself. */
export async function storeVuid(userId, vuid) {
  must(await admin().auth.admin.updateUserById(userId, { app_metadata: { tide_vuid: vuid } }));
}

/** Whether schema.sql has been run, so the page can say so instead of failing oddly. */
export async function schemaMissing() {
  const { error } = await admin().from("payouts").select("id").limit(1);
  return !!error && /does not exist|could not find the table/i.test(error.message);
}

export const payees = async () =>
  must(await admin().from("payees").select("*").order("created_at", { ascending: false }));

export const addPayee = async (row) =>
  must(await admin().from("payees").insert(row).select().single());

export const payouts = async () =>
  must(await admin().from("payouts").select("*").order("created_at", { ascending: false }));

export const payout = async (id) =>
  must(await admin().from("payouts").select("*").eq("id", id).maybeSingle());

export const addPayout = async (row) =>
  must(await admin().from("payouts").insert(row).select().single());

export const updatePayout = async (id, fields) =>
  must(await admin().from("payouts").update(fields).eq("id", id).select().single());
