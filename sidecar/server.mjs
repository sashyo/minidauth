// A tiny sealing service for apps (Twenty, Cal, Formbricks).
//
// It holds no key and, importantly, it holds no reading identity of its own. minidauth and the ORK
// cohort do the crypto; this only orchestrates it. /open decrypts strictly on behalf of the end user
// named in a verified IAM token: the caller must present that user's token, the sidecar verifies it,
// and asks minidauth to voucher a decrypt for THAT user. minidauth's quorum-governed grant then
// decides whether the user holds the reading role. There is no standing "reader" here to borrow, so
// an unauthenticated caller who reaches /open gets nothing.
//
//   MINIDAUTH_URL=…  MINIDAUTH_TOKEN=…  MINIDAUTH_OPS_TOKEN=…  \
//   MINIDAUTH_READER_ROLE=crm-reader \                # capability the user must hold, NOT an identity
//   MINIDAUTH_AUTH_MODE=hs256  MINIDAUTH_AUTH_SECRET=…  MINIDAUTH_AUTH_UID_CLAIM=sub \
//   node --import ./register.mjs server.mjs

import { createServer } from "node:http";
import { sealFields, openValues, signPayload, verifyCohortSignature, proxyConfig, proxyDecryptPolicy, proxyMintUserDoken, proxyVoucher, proxyRevoke } from "./seal.mjs";
import { verifyUserToken } from "./verify.mjs";

const PORT = Number(process.env.PORT ?? 3020);
// The capability a quorum must have granted the user, keyed to the user's own uid (not a service
// account). Revoke it for a user in minidauth and every open below stops working for them, with no
// change to the app. That is the whole point.
const READER_ROLE = process.env.MINIDAUTH_READER_ROLE ?? "response-reader";

const readBody = (req) => new Promise((resolve, reject) => {
  let b = ""; req.on("data", (c) => (b += c));
  req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch (e) { reject(e); } });
  req.on("error", reject);
});
// CORS is open here for the Level 2b browser client demo. Lock it to the app's origin in a real
// deployment; the relay endpoints below carry no app credential a browser could steal regardless.
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Methods": "POST, GET, OPTIONS" };
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json", ...CORS }); res.end(JSON.stringify(obj)); };
const sendRaw = (res, code, text) => { res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", ...CORS }); res.end(text); };

// The end user's token: "Authorization: Bearer <token>", or a { userToken } body field for callers
// that cannot set headers. Whichever is present, it is verified before it is trusted.
const tokenFrom = (req, body) => {
  const auth = req.headers["authorization"];
  if (auth && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, "").trim();
  if (body && typeof body.userToken === "string") return body.userToken;
  return null;
};

const server = createServer(async (req, res) => {
  try {
    if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }

    if (req.method === "GET" && req.url === "/health")
      return send(res, 200, { status: "up", role: READER_ROLE, authMode: process.env.MINIDAUTH_AUTH_MODE ?? "hs256", standingReader: false });

    // ---- Level 2b relay: let a client that holds its own session key decrypt for itself ----
    // The sidecar attaches its relying-party credential and forwards. It mints no identity and never
    // sees plaintext: the decrypt runs in the client, the sidecar only relays vouchers and config.
    if (req.method === "POST" && req.url === "/proxy/config")
      return send(res, 200, await proxyConfig());
    if (req.method === "POST" && req.url === "/proxy/decrypt-policy")
      return send(res, 200, await proxyDecryptPolicy());
    if (req.method === "POST" && req.url === "/proxy/user-token") {
      const { userToken, sessionKey } = await readBody(req); // userToken proves who; sessionKey binds the doken
      // Pin the doken to THIS sidecar's role, so a doken minted here can only ever read as READER_ROLE.
      return send(res, 200, await proxyMintUserDoken(userToken, sessionKey, READER_ROLE));
    }
    if (req.method === "POST" && req.url === "/proxy/voucher") {
      const b = await readBody(req); // { voucherRequest, doken, popTs, popNonce, popSig }
      return sendRaw(res, 200, await proxyVoucher({ role: READER_ROLE, ...b }));
    }
    if (req.method === "POST" && req.url === "/proxy/revoke") {
      // Revocation is a SERVER-only operation: only the app (at logout) may revoke a session, never a
      // browser. A browser could otherwise post any session id it holds a token for and cut off that
      // session's decryption (a denial of service). If MINIDAUTH_REVOKE_SECRET is set, require it; and
      // in any case refuse a request that carries an Origin header (i.e. one made from a browser), since
      // the server-to-server call from the app carries none.
      const secret = process.env.MINIDAUTH_REVOKE_SECRET;
      const provided = req.headers["x-minidauth-revoke-secret"];
      const fromBrowser = Boolean(req.headers["origin"]);
      if (secret ? provided !== secret : fromBrowser) {
        return send(res, 401, { error: "session revocation is a server-only operation" });
      }
      const { sid } = await readBody(req); // the app's server-derived session id, revoked at logout
      return send(res, 200, await proxyRevoke(sid));
    }

    if (req.method === "POST" && req.url === "/seal") {
      // { fields: { key: plaintextString } } -> { sealed: { key: ciphertextB64 } }
      // Encryption is not the sensitive operation (anyone may write to the vault); the reading gate is
      // on /open. Put /seal behind the same network boundary as the rest of the backend.
      // Returns marker-included values. A client-forged "ms1:" prefix does not skip sealing: sealField
      // seals anything that is not verifiable genuine ciphertext.
      const { fields } = await readBody(req);
      const entries = Object.entries(fields || {});
      const out = await sealFields(entries.map(([, v]) => String(v))); // ONE fan-out for all fields
      const sealed = {};
      entries.forEach(([k], i) => { sealed[k] = out[i]; });
      return send(res, 200, { sealed });
    }

    if (req.method === "POST" && req.url === "/open") {
      // Server-side decryption from a bearer user token, NO session key and NO proof of possession.
      // That is the weaker "the server can read" model, and it is a decryption oracle for anyone
      // holding a user token. It is OFF by default: the client-side path (/proxy/voucher, gated on the
      // browser's session key) is the only decryption path unless a deployment explicitly opts in.
      if (!(process.env.MINIDAUTH_ALLOW_SERVER_OPEN === "true" || process.env.MINIDAUTH_ALLOW_SERVER_OPEN === "1")) {
        return send(res, 403, { error: "server-side /open is disabled; decrypt via the client (session key + proof of possession)" });
      }
      // { fields: { key: ciphertextB64 } } -> { fields: { key: plaintextString } }
      // Gated on the END USER's verified token: decrypt runs as that user, and only if minidauth's
      // quorum grant says the user holds READER_ROLE.
      const body = await readBody(req);
      const token = tokenFrom(req, body);
      if (!token) return send(res, 401, { error: "missing user token" });
      let uid;
      try {
        ({ uid } = verifyUserToken(token));
      } catch (e) {
        return send(res, 401, { error: `invalid user token: ${e.message}` });
      }
      const entries = Object.entries(body.fields || {});
      // Forward the user's own token so minidauth verifies the identity at its voucher boundary, not
      // just here. When minidauth has user-token checking on, the uid it gates on comes from this token.
      const plains = await openValues(uid, READER_ROLE, entries.map(([, v]) => String(v)), token); // ONE fan-out, as this user
      const out = {};
      entries.forEach(([k], i) => { out[k] = plains[i]; });
      return send(res, 200, { fields: out });
    }

    if (req.method === "POST" && req.url === "/sign") {
      // Have the ORK cohort threshold-sign a payload on behalf of the verified end user, iff minidauth's
      // quorum grant says that user holds READER_ROLE. The signature is an ordinary VVK signature anyone
      // can verify with the vendor public key - no key is assembled here, so this is not a signing oracle
      // an unauthenticated caller can borrow: without a valid user token there is no signer.
      const body = await readBody(req);
      const token = tokenFrom(req, body);
      if (!token) return send(res, 401, { error: "missing user token" });
      let uid;
      try { ({ uid } = verifyUserToken(token)); }
      catch (e) { return send(res, 401, { error: `invalid user token: ${e.message}` }); }
      const payload = typeof body.payload === "string" ? body.payload : null;
      if (!payload) return send(res, 400, { error: "payload (a string) is required" });
      const signature = await signPayload(uid, READER_ROLE, payload, token); // gated by the grant, cohort-signed
      return send(res, 200, { signature });
    }

    if (req.method === "POST" && req.url === "/verify") {
      // Public: check a cohort signature over a payload against the vendor public key. No identity, no
      // secret - the whole point is that anyone can verify, so this endpoint carries no auth.
      const { payload, signature } = await readBody(req);
      if (typeof payload !== "string") return send(res, 400, { error: "payload (a string) is required" });
      return send(res, 200, await verifyCohortSignature(payload, signature));
    }

    send(res, 404, { error: "not found" });
  } catch (e) {
    // minidauth refuses the voucher when the user does not hold the role -> 403, not 502.
    const refused = /does not hold|will not voucher|403/.test(String(e.message || e));
    send(res, refused ? 403 : 502, { error: String(e.message || e) });
  }
});

server.listen(PORT, () => console.log(`minidauth-seal on http://localhost:${PORT}  (decrypts only as a verified user who holds ${READER_ROLE}; no standing reader)`));
