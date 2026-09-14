// Supabase side of Vault.
//
// Two kinds of key are used here, and the difference is the whole point:
//   - the ANON (publishable) key does auth only — sign in, validate a token, refresh, sign out. It
//     is safe to hold, and it is the ONLY key the browser's session ever rides on (server-set,
//     httpOnly). The browser itself never receives a Supabase key.
//   - the SERVICE-ROLE (secret) key bypasses row-level security. It never leaves this server, and
//     every sensitive column it touches is stored as ciphertext, so a leak of it reads nothing.
import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPABASE_URL;
const ANON = process.env.SUPABASE_ANON_KEY;            // auth only; never bypasses RLS
const SECRET = process.env.SUPABASE_SERVICE_ROLE_KEY;  // bypasses RLS; never in the browser

export function missingConfig() {
  return Object.entries({ SUPABASE_URL: URL, SUPABASE_ANON_KEY: ANON, SUPABASE_SERVICE_ROLE_KEY: SECRET })
    .filter(([, v]) => !v).map(([k]) => k);
}

// A client on the anon key, no session persistence — one per call, so nothing is shared between users.
const authClient = () => createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });
const admin = () => createClient(URL, SECRET, { auth: { persistSession: false } });
const must = ({ data, error }) => { if (error) throw new Error(error.message); return data; };
const userOut = (u) => (u ? { id: u.id, email: u.email } : null);

// ------------------------------------------------------------------- auth
/** Exchange email + password for a session. Throws on bad credentials. */
export async function signIn(email, password) {
  const { data, error } = await authClient().auth.signInWithPassword({ email, password });
  if (error) throw Object.assign(new Error(error.message), { status: 400 });
  return { session: data.session, user: userOut(data.user) };
}

/** Who this access token belongs to, as Supabase itself answers it — or null if it is not valid. */
export async function userFromToken(accessToken) {
  if (!accessToken || !URL) return null;
  const { data, error } = await authClient().auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return userOut(data.user);
}

/** Trade a refresh token for a fresh session, or null if it can no longer be refreshed. */
export async function refresh(refreshToken) {
  if (!refreshToken) return null;
  const { data, error } = await authClient().auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data?.session) return null;
  return { session: data.session, user: userOut(data.user) };
}

/** Best-effort revoke of a refresh token's session. Clearing the cookies is what actually logs out. */
export async function signOut(accessToken) {
  if (!accessToken) return;
  try { await admin().auth.admin.signOut(accessToken); } catch { /* token already gone */ }
}

// --------------------------------------------------------------- records
/** Records: name is clear (for the list), every sensitive field is a ciphertext blob under `ct`. */
export async function records() {
  const rows = must(await admin().from("vault_records").select("*").order("created_at", { ascending: false }));
  return rows.map((r) => ({ id: r.id, name: r.name, ref: r.ref, ct: r.ciphertext ?? {}, created: r.created_at?.slice(0, 10) }));
}
export async function addRecord({ name, ref, ct, by }) {
  const row = must(await admin().from("vault_records").insert({ name, ref, ciphertext: ct, created_by: by }).select().single());
  return { id: row.id, name: row.name, ref: row.ref, ct: row.ciphertext ?? {}, created: row.created_at?.slice(0, 10) };
}
