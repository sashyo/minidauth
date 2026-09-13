/**
 * Everything an application is allowed to ask minidauth for.
 *
 * Deliberately small, and the same file whatever owns your login. An integration is three calls:
 * send the browser somewhere to prove a Tide identity, turn the reply into a proven vuid, and read
 * what that identity has been granted.
 *
 * The token this uses holds the `relying-party` role, which grants nothing on its own. It is not what
 * makes the roles trustworthy, since those come from a grant record the network attested. It is
 * there because starting a sign-in spends licence quota and because the grant record should not be
 * readable by anyone who can reach the port. Leaking it costs quota and a look at who holds what; it
 * hands nobody a role.
 *
 * It authenticates this app to minidauth, not minidauth to this app, so anywhere but localhost the
 * connection between the two wants TLS like any other trusted call.
 */
import crypto from "node:crypto";

const BASE = () => process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const TOKEN = () => process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";
const CLIENT_NAME = () => process.env.MINIDAUTH_CLIENT_NAME;
const CLIENT_KEY = () => process.env.MINIDAUTH_CLIENT_KEY;

const b64url = (b) => Buffer.from(b).toString("base64url");

/**
 * Prove we hold the private key, without sending anything reusable.
 *
 * Signed fresh for each call and good for a minute, so an assertion seen in transit is worth
 * nothing by the time anyone could use it. minidauth also refuses a jti it has seen before.
 */
function assertion() {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }));
  const claims = b64url(JSON.stringify({
    iss: CLIENT_NAME(),
    aud: BASE(),
    iat: now,
    exp: now + 60,
    jti: crypto.randomUUID(),
  }));
  const key = crypto.createPrivateKey({
    key: Buffer.from(CLIENT_KEY(), "base64"),
    format: "der",
    type: "pkcs8",
  });
  const signature = crypto.sign(null, Buffer.from(`${header}.${claims}`), key);
  return `${header}.${claims}.${b64url(signature)}`;
}

/** A signing key if there is one, the shared token otherwise. */
function authorization() {
  return CLIENT_NAME() && CLIENT_KEY()
    ? "Assertion " + assertion()
    : "Bearer " + TOKEN();
}

async function call(path, init = {}) {
  const res = await fetch(BASE() + path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: authorization(),
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

// ---------------------------------------------------------------------------
// Tideless: acting for a user who has no Tide account of their own.
//
// The three calls above link a Tide identity to each user. These let the app
// encrypt, sign and decrypt on behalf of a user who never signs in to Tide —
// the app's own user id is the subject, and a role a quorum granted it is the
// gate. See examples/tideless and examples/tideless-web.

/** Fetch a raw (unparsed) body, for the voucher endpoints which return a voucher verbatim. */
async function raw(path, init = {}) {
  const res = await fetch(BASE() + path, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: authorization(), ...(init.headers ?? {}) },
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = text;
    try { msg = JSON.parse(text).error ?? text; } catch { /* not json */ }
    throw new Error(msg || `${res.status} ${res.statusText}`);
  }
  return text;
}

/** Public config a browser needs to reach the network and (de)crypt: key id, home ORK, policy bytes. */
export async function vaultConfig() {
  const [cfg, enc, dec] = await Promise.all([
    call("/tide/enclave/config"),
    call("/vault/encrypt-policy"),
    call("/vault/decrypt-policy"),
  ]);
  return { vvkId: cfg.vvkId, homeOrkUrl: cfg.homeOrkUrl, encryptPolicy: enc.policy, decryptPolicy: dec.policy };
}

/** Mint an encrypt (vendorsign) voucher. Any configured operator may; the app token is enough. */
export function signVoucher(voucherRequest) {
  return raw("/tide/vouchers", { method: "POST", body: JSON.stringify({ voucherRequest }) });
}

/**
 * Mint a decrypt (vendordecrypt) voucher for `uid`, gated on it holding `role`.
 *
 * The uid is decided by the app server (from its own verified session), never by the browser, so a
 * page cannot voucher a read for a user other than the one calling.
 */
export function decryptVoucher(uid, role, voucherRequest) {
  return raw("/vault/voucher", { method: "POST", body: JSON.stringify({ uid, role, voucherRequest }) });
}
