/* Everything this app is allowed to ask minidauth for.
 *
 * The token here holds the relying-party role, which grants nothing on its own. It can start a Tide
 * sign-in, finish one, and read what an identity has been granted. It cannot approve a change or
 * touch the vendor key, so leaking it does not hand anybody a role.
 */
const BASE = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const TOKEN = process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";

async function call(path, init = {}) {
  const res = await fetch(BASE + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + TOKEN,
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(body?.error ?? `${res.status} ${res.statusText}`);
  return body;
}

/** Where to send the browser to prove a Tide identity. */
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
 * rather than claimed. That is why this app can store it without checking anything itself.
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
 * Read every time rather than cached on the user row. A revoked role has to stop working when the
 * quorum says so, not when this app next happens to refresh.
 */
export function rolesFor(vuid) {
  return call("/iga/grants/" + encodeURIComponent(vuid)).then((r) => r.roles ?? []);
}
