/**
 * Everything an application is allowed to ask minidauth for.
 *
 * Deliberately small, and the same file whatever owns your login. An integration is three calls:
 * send the browser somewhere to prove a Tide identity, turn the reply into a proven vuid, and read
 * what that identity has been granted.
 *
 * The token this uses holds the `relying-party` role, which grants nothing on its own. It can start
 * a sign-in, finish one, and read grants. It cannot approve a change or touch the vendor key, so
 * leaking it hands nobody a role.
 */
const BASE = () => process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const TOKEN = () => process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";

async function call(path, init = {}) {
  const res = await fetch(BASE() + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + TOKEN(),
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(body?.error ?? `${res.status} ${res.statusText}`);
  return body;
}

/**
 * Where to send the browser to prove a Tide identity.
 *
 * `redirectUri` has to be one minidauth has signed, or the enclave will not return to it. The
 * examples register theirs at setup rather than leaving you to find that out.
 */
export function loginUrl(sessionId, redirectUri) {
  return call("/tide/enclave/login-url", {
    method: "POST",
    body: JSON.stringify({ sessionId, redirectUri }),
  }).then((r) => r.url);
}

/**
 * Turn the enclave's reply into a proven identity.
 *
 * minidauth verifies the blind signature before it answers, so the vuid that comes back is proven
 * rather than claimed. Your app still has to check the reply belongs to a sign-in it started, for
 * the account that started it.
 */
export function completeLogin(encryptedVendorData, sessionId) {
  return call("/tide/enclave/callback", {
    method: "POST",
    body: JSON.stringify({ encryptedVendorData, sessionId }),
  });
}

/**
 * What an identity has been granted.
 *
 * Read on every request rather than cached on the user record. A revoked role has to stop working
 * when the quorum says so, not when your app next happens to refresh. This is the call that makes
 * authorisation something your database cannot decide.
 */
export function rolesFor(vuid) {
  return call("/iga/grants/" + encodeURIComponent(vuid)).then((r) => r.roles ?? []);
}
