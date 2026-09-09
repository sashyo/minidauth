import { createClerkClient } from "@clerk/backend";

const SECRET = process.env.CLERK_SECRET_KEY;
const PUBLISHABLE = process.env.CLERK_PUBLISHABLE_KEY;

export const publishableKey = () => PUBLISHABLE;

export function missingConfig() {
  return Object.entries({ CLERK_SECRET_KEY: SECRET, CLERK_PUBLISHABLE_KEY: PUBLISHABLE })
    .filter(([, v]) => !v).map(([k]) => k);
}

const clerk = () => createClerkClient({ secretKey: SECRET, publishableKey: PUBLISHABLE });

/**
 * Who is making this request, according to Clerk.
 *
 * Clerk's session cookie is verified against its own keys, so this app never handles a password and
 * never decides for itself who somebody is.
 */
export async function currentUser(req) {
  const requestState = await clerk().authenticateRequest(
    new Request(`${process.env.APP_URL ?? "http://localhost:3003"}${req.originalUrl}`, {
      headers: new Headers(Object.entries(req.headers).map(([k, v]) => [k, String(v)])),
    }),
  );
  const auth = requestState.toAuth();
  if (!auth?.userId) return null;
  const user = await clerk().users.getUser(auth.userId);
  return {
    id: user.id,
    email: user.primaryEmailAddress?.emailAddress,
    // privateMetadata, so the browser cannot see or set it.
    vuid: user.privateMetadata?.tideVuid ?? null,
  };
}

/**
 * Record the Tide identity against the Clerk user.
 *
 * `privateMetadata` rather than `publicMetadata`, because this is a link, not a profile field, and
 * nothing in the browser should be able to write it. Roles are deliberately not stored here: Clerk
 * can put metadata into a session token, and a role in a token this app can mint is a role this app
 * can grant itself.
 */
/** The stored user, by id, for the callback that cannot ask Clerk who is calling. */
export async function userById(userId) {
  const user = await clerk().users.getUser(userId);
  return {
    id: user.id,
    email: user.primaryEmailAddress?.emailAddress,
    vuid: user.privateMetadata?.tideVuid ?? null,
  };
}

export async function storeVuid(userId, vuid) {
  await clerk().users.updateUserMetadata(userId, { privateMetadata: { tideVuid: vuid } });
}
