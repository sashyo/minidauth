import { createClient } from "@supabase/supabase-js";

const URL = process.env.SUPABASE_URL;                    // https://xxxx.supabase.co
const ANON = process.env.SUPABASE_ANON_KEY;              // safe in the browser
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY;   // never in the browser

export const publicConfig = () => ({ url: URL, anonKey: ANON });

export function missingConfig() {
  return Object.entries({ SUPABASE_URL: URL, SUPABASE_ANON_KEY: ANON,
    SUPABASE_SERVICE_ROLE_KEY: SERVICE })
    .filter(([, v]) => !v).map(([k]) => k);
}

/**
 * Who this request belongs to, according to Supabase.
 *
 * The access token is verified by Supabase itself rather than parsed here, so this app never
 * decides for itself who somebody is.
 */
export async function userFor(accessToken) {
  if (!accessToken) return null;
  const anon = createClient(URL, ANON);
  const { data, error } = await anon.auth.getUser(accessToken);
  if (error || !data?.user) return null;
  return {
    id: data.user.id,
    email: data.user.email,
    // app_metadata, not user_metadata: the user can write their own user_metadata.
    vuid: data.user.app_metadata?.tide_vuid ?? null,
  };
}

/**
 * Record the Tide identity against the Supabase user.
 *
 * `app_metadata` and the service role key, because `user_metadata` is writable by the user
 * themselves and this is a link, not a preference.
 *
 * Supabase copies `app_metadata` into the access token, which is exactly why the vuid goes here and
 * roles do not. A role in a token this project can mint is a role this project can grant itself.
 */
export async function storeVuid(userId, vuid) {
  const admin = createClient(URL, SERVICE, { auth: { persistSession: false } });
  const { error } = await admin.auth.admin.updateUserById(userId, {
    app_metadata: { tide_vuid: vuid },
  });
  if (error) throw new Error("could not store the vuid: " + error.message);
}
