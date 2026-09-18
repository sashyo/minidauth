// Verify the end user's token and return the authenticated uid, nothing else.
//
// This is what stops the sidecar being a confused deputy. The old design injected a fixed reader
// identity, so anyone who could reach /open borrowed its decryption authority. Now every /open must
// carry the caller's own IAM token; the sidecar verifies it and decrypts as THAT user.
//
// Deliberate rule: the token proves WHO (identity only). It does NOT carry the authorization to
// decrypt. minidauth's quorum-governed grant decides whether the verified user holds the reading
// role, so we never trust an authorization/role claim out of a plain JWT (that would just move the
// mutable-role-table problem into a token). If you front this with an IdP whose role claims are
// threshold-signed and attested, you can lift the role from the token instead; a plain HS256 claim,
// no.
//
// Token-agnostic on purpose, so Twenty (APP_SECRET) and Cal (NEXTAUTH_SECRET) can share one sidecar:
//   MINIDAUTH_AUTH_MODE=hs256            (the only mode today)
//   MINIDAUTH_AUTH_SECRET=…              HMAC secret the IAM signs user tokens with
//   MINIDAUTH_AUTH_UID_CLAIM=sub         dotted path to the uid claim (default "sub")
//   MINIDAUTH_AUTH_ISSUER=… (optional)   require this iss
//   MINIDAUTH_AUTH_AUDIENCE=… (optional) require this aud

import { createHmac, timingSafeEqual, createPublicKey, verify as edVerify } from "node:crypto";

const b64urlToBuf = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
const b64urlJson = (s) => JSON.parse(b64urlToBuf(s).toString("utf8"));
// dotted-path getter so the uid can live at "sub", "user.id", etc.
const dig = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);

/** Verify a user token per MINIDAUTH_AUTH_MODE. Returns { uid, payload }. Throws on any failure. */
export function verifyUserToken(token) {
  const mode = process.env.MINIDAUTH_AUTH_MODE ?? "hs256";
  if (mode === "eddsa") return verifyEddsa(token);
  if (mode === "hs256") return verifyHs256(token);
  throw new Error(`unknown MINIDAUTH_AUTH_MODE: ${mode}`);
}

// Ed25519: the app signs with a private key, this holds only the public key (MINIDAUTH_AUTH_PUBLIC_KEY,
// SPKI base64). No shared secret, so nothing here forges a user even if the whole sidecar leaks.
let _pub;
function eddsaPublicKey() {
  if (_pub !== undefined) return _pub;
  const b64 = process.env.MINIDAUTH_AUTH_PUBLIC_KEY;
  _pub = b64 ? createPublicKey({ key: Buffer.from(b64, "base64"), format: "der", type: "spki" }) : null;
  return _pub;
}

function verifyEddsa(token) {
  const key = eddsaPublicKey();
  if (!key) throw new Error("MINIDAUTH_AUTH_PUBLIC_KEY is not set");
  const uidClaim = process.env.MINIDAUTH_AUTH_UID_CLAIM ?? "sub";
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [h, p, sig] = parts;
  const header = b64urlJson(h);
  if (header.alg !== "EdDSA") throw new Error(`unexpected alg ${header.alg}`);
  if (!edVerify(null, Buffer.from(`${h}.${p}`, "ascii"), key, b64urlToBuf(sig))) throw new Error("bad signature");
  return checkClaims(b64urlJson(p), uidClaim);
}

// Shared claim checks (exp/nbf/iss/aud + uid) for both modes.
function checkClaims(payload, uidClaim) {
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp != null && now >= payload.exp) throw new Error("token expired");
  if (payload.nbf != null && now < payload.nbf) throw new Error("token not yet valid");
  const iss = process.env.MINIDAUTH_AUTH_ISSUER;
  if (iss && payload.iss !== iss) throw new Error("bad issuer");
  const aud = process.env.MINIDAUTH_AUTH_AUDIENCE;
  if (aud && ![].concat(payload.aud ?? []).includes(aud)) throw new Error("bad audience");
  const uid = dig(payload, uidClaim);
  if (!uid) throw new Error(`no ${uidClaim} claim in token`);
  return { uid: String(uid), payload };
}

function verifyHs256(token) {
  const secret = process.env.MINIDAUTH_AUTH_SECRET;
  if (!secret) throw new Error("MINIDAUTH_AUTH_SECRET is not set");
  const uidClaim = process.env.MINIDAUTH_AUTH_UID_CLAIM ?? "sub";

  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const [h, p, sig] = parts;

  const header = b64urlJson(h);
  if (header.alg !== "HS256") throw new Error(`unexpected alg ${header.alg}`); // pin the algorithm

  const expected = createHmac("sha256", secret).update(`${h}.${p}`).digest();
  const got = b64urlToBuf(sig);
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) throw new Error("bad signature");

  const payload = b64urlJson(p);
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp != null && now >= payload.exp) throw new Error("token expired");
  if (payload.nbf != null && now < payload.nbf) throw new Error("token not yet valid");

  const iss = process.env.MINIDAUTH_AUTH_ISSUER;
  if (iss && payload.iss !== iss) throw new Error("bad issuer");
  const aud = process.env.MINIDAUTH_AUTH_AUDIENCE;
  if (aud && ![].concat(payload.aud ?? []).includes(aud)) throw new Error("bad audience");

  const uid = dig(payload, uidClaim);
  if (!uid) throw new Error(`no ${uidClaim} claim in token`);
  return { uid: String(uid), payload };
}
