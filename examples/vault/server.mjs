// Vault — server.
//
// Supabase owns the login. minidauth holds the vendor key and issues the vouchers that let the
// signed-in user's browser encrypt and decrypt with no Tide account (tideless). This server:
//   - signs the user in against Supabase and keeps the session in httpOnly cookies the browser's
//     scripts can never read (so an XSS cannot steal the token),
//   - refreshes that session transparently, and enforces a CSRF token on every state change,
//   - proxies the two vouchers to minidauth, gating the decrypt voucher on the user's role,
//   - stores records (ciphertext only) and signed releases in Supabase.
//
// It requires Supabase to be configured; there is no demo mode. See README for the env it needs and
// for putting it behind TLS in production.

import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as db from "./db.mjs";
import { vaultConfig, signVoucher, decryptVoucher, rolesFor } from "../shared/minidauth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT ?? 3007;
const ROLE = process.env.VAULT_ROLE ?? "vault-reader";

// Fail fast rather than serve a half-configured app.
const missing = db.missingConfig();
if (missing.length) {
  console.error(`Vault needs these environment variables set: ${missing.join(", ")}. See README.`);
  process.exit(1);
}
if (!process.env.MINIDAUTH_CLIENT_KEY && (process.env.NODE_ENV === "production")) {
  console.warn("[warn] MINIDAUTH_CLIENT_KEY is not set: the app is authenticating to minidauth with a " +
    "shared bearer token. In production, use the signing-key assertion (MINIDAUTH_CLIENT_NAME + " +
    "MINIDAUTH_CLIENT_KEY). See ../shared/minidauth.js.");
}

const app = express();
// Behind a TLS-terminating proxy, trust it so secure cookies and client IPs are read correctly.
if (process.env.TRUST_PROXY) app.set("trust proxy", Number(process.env.TRUST_PROXY) || 1);

// --- cookies --------------------------------------------------------------
const COOKIE_SECURE = process.env.COOKIE_SECURE
  ? process.env.COOKIE_SECURE === "true"
  : process.env.NODE_ENV === "production";
const base = { httpOnly: true, secure: COOKIE_SECURE, sameSite: "lax", path: "/" };
const HOUR = 3600 * 1000, MONTH = 30 * 24 * HOUR;

function setAuthCookies(res, session) {
  res.cookie("vault_at", session.access_token, { ...base, maxAge: HOUR });
  res.cookie("vault_rt", session.refresh_token, { ...base, maxAge: MONTH });
}
function rotateCsrf(res) {
  const token = crypto.randomBytes(32).toString("base64url");
  res.cookie("vault_csrf", token, { ...base, httpOnly: false, maxAge: MONTH });
  return token;
}
function clearSession(res) {
  for (const c of ["vault_at", "vault_rt"]) res.clearCookie(c, { ...base });
}

// --- security headers -----------------------------------------------------
// Locked down to exactly what this app loads: its own origin, tide-js from esm.sh, Google Fonts,
// and the ORK network it must reach to (de)crypt. Everything else is denied.
app.use((_req, res, next) => {
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self' https://esm.sh 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://esm.sh https://*.tideprotocol.com",
    "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'",
  ].join("; "));
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  if (COOKIE_SECURE) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});

app.use(cookieParser());
app.use(express.json({ limit: "512kb" }));
// Everyone gets a CSRF token to echo back on state-changing calls.
app.use((req, res, next) => { if (!req.cookies.vault_csrf) rotateCsrf(res); next(); });
app.use(express.static(join(HERE, "public")));

// --- rate limiting (in-memory; use a shared store behind multiple instances) ---
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, windowMs).unref?.();
  return (req, res, next) => {
    const key = (req.ip || "?") + ":" + req.path;
    const now = Date.now();
    let e = hits.get(key);
    if (!e || e.reset < now) { e = { count: 0, reset: now + windowMs }; hits.set(key, e); }
    if (++e.count > max) return res.status(429).json({ error: "too many requests, slow down" });
    next();
  };
}
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const cryptoLimit = rateLimit({ windowMs: 60 * 1000, max: 60 });

// --- middleware -----------------------------------------------------------
// Resolve the session, refreshing transparently when the access token has expired.
async function resolveSession(req, res) {
  const at = req.cookies.vault_at;
  if (at) { const u = await db.userFromToken(at).catch(() => null); if (u) return u; }
  const rt = req.cookies.vault_rt;
  if (rt) {
    const r = await db.refresh(rt).catch(() => null);
    if (r?.session) { setAuthCookies(res, r.session); return r.user; }
  }
  return null;
}
const authRequired = async (req, res, next) => {
  const u = await resolveSession(req, res);
  if (!u) { clearSession(res); return res.status(401).json({ error: "sign in first" }); }
  req.user = u;
  next();
};
// Double-submit CSRF: the header must match the cookie. A cross-site page cannot read the cookie to
// forge the header, and SameSite=Lax already keeps the cookie off cross-site POSTs.
const requireCsrf = (req, res, next) => {
  const header = req.get("x-csrf-token"), cookie = req.cookies.vault_csrf;
  if (!header || !cookie || header !== cookie) return res.status(403).json({ error: "bad or missing CSRF token" });
  next();
};

// --- auth -----------------------------------------------------------------
app.post("/api/login", loginLimit, requireCsrf, async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) return res.status(400).json({ error: "email and password are required" });
  try {
    const { session } = await db.signIn(String(email), String(password));
    setAuthCookies(res, session);
    rotateCsrf(res); // new token on privilege change
    res.json({ ok: true });
  } catch (e) {
    res.status(401).json({ error: "sign-in failed" }); // do not leak which of email/password was wrong
  }
});

app.post("/api/logout", requireCsrf, async (req, res) => {
  await db.signOut(req.cookies.vault_at).catch(() => {});
  clearSession(res);
  res.json({ ok: true });
});

// Who is signed in, and what roles their id holds (read live from minidauth on every request).
app.get("/api/session", async (req, res) => {
  const u = await resolveSession(req, res);
  if (!u) return res.status(401).json({ error: "not signed in" });
  const roles = await rolesFor(u.id).catch(() => []);
  const pending = roles.includes(ROLE) ? null : await db.openAccessRequestFor(u.id);
  res.json({ user: u.email ?? u.id, uid: u.id, roles, gateRole: ROLE, pendingRequest: pending });
});

// --- vault ----------------------------------------------------------------
// Public config + policy bytes the browser needs to reach the network.
app.get("/api/vault/config", authRequired, async (_req, res) => {
  try { res.json(await vaultConfig()); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

const auditDetail = (req) => {
  const c = req.body?.context;
  return c && typeof c === "object" ? { field: String(c.field ?? "").slice(0, 40), record: String(c.record ?? "").slice(0, 64) } : {};
};

// Encrypt voucher (vendorsign) — any signed-in user may seal a field.
app.post("/api/vault/voucher/sign", authRequired, requireCsrf, cryptoLimit, async (req, res) => {
  try {
    const out = await signVoucher(req.body.voucherRequest);
    db.logActivity({ type: "seal", actor: req.user.id, actorEmail: req.user.email, allowed: true, detail: auditDetail(req) });
    res.type("application/json").send(out);
  } catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// Decrypt voucher (vendordecrypt) — gated on the user's id holding the role. The uid is taken from
// the verified session here, never from the browser. Every attempt is logged, allowed or denied.
app.post("/api/vault/voucher/decrypt", authRequired, requireCsrf, cryptoLimit, async (req, res) => {
  try {
    const out = await decryptVoucher(req.user.id, ROLE, req.body.voucherRequest);
    db.logActivity({ type: "reveal", actor: req.user.id, actorEmail: req.user.email, allowed: true, detail: auditDetail(req) });
    res.type("application/json").send(out);
  } catch (e) {
    db.logActivity({ type: "reveal_denied", actor: req.user.id, actorEmail: req.user.email, allowed: false, detail: auditDetail(req) });
    res.status(403).json({ error: "the network declined — " + String(e.message || e) });
  }
});

// Records — ciphertext in, ciphertext out. The plaintext only ever exists in a browser.
app.get("/api/vault/records", authRequired, async (_req, res) => {
  try { res.json(await db.records()); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});
app.post("/api/vault/records", authRequired, requireCsrf, async (req, res) => {
  const { name, ref, ct } = req.body ?? {};
  if (typeof name !== "string" || !name.trim() || name.length > 200) return res.status(400).json({ error: "a name (<=200 chars) is required" });
  if (ref != null && (typeof ref !== "string" || ref.length > 120)) return res.status(400).json({ error: "ref must be a string (<=120 chars)" });
  const fields = ct && typeof ct === "object" ? ct : {};
  for (const [k, v] of Object.entries(fields)) {
    if (!["bank", "tax", "notes"].includes(k)) return res.status(400).json({ error: `unknown field ${k}` });
    if (typeof v !== "string" || v.length > 100000) return res.status(400).json({ error: `field ${k} is not a valid ciphertext` });
  }
  try { res.json(await db.addRecord({ name: name.trim(), ref: ref?.trim() || null, ct: fields, by: req.user.id })); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

const uuidRe = /^[0-9a-f-]{36}$/i;
function validCt(ct) {
  const fields = ct && typeof ct === "object" ? ct : {};
  for (const [k, v] of Object.entries(fields)) {
    if (!["bank", "tax", "notes"].includes(k)) return `unknown field ${k}`;
    if (typeof v !== "string" || v.length > 100000) return `field ${k} is not a valid ciphertext`;
  }
  return null;
}

// Edit a record. The browser re-encrypts changed fields and sends fresh ciphertext.
app.put("/api/vault/records/:id", authRequired, requireCsrf, async (req, res) => {
  if (!uuidRe.test(req.params.id)) return res.status(400).json({ error: "bad id" });
  const { name, ref, ct } = req.body ?? {};
  if (name != null && (typeof name !== "string" || !name.trim() || name.length > 200)) return res.status(400).json({ error: "name must be <=200 chars" });
  const bad = ct != null ? validCt(ct) : null;
  if (bad) return res.status(400).json({ error: bad });
  try { res.json(await db.updateRecord({ id: req.params.id, name: name?.trim(), ref: ref == null ? undefined : (ref.trim() || null), ct })); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// Delete a record.
app.delete("/api/vault/records/:id", authRequired, requireCsrf, async (req, res) => {
  if (!uuidRe.test(req.params.id)) return res.status(400).json({ error: "bad id" });
  try { await db.deleteRecord(req.params.id); db.logActivity({ type: "delete", actor: req.user.id, actorEmail: req.user.email, allowed: true, detail: { record: req.params.id } }); res.json({ ok: true }); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// The activity feed: the audit trail plus access requests, newest first.
app.get("/api/vault/activity", authRequired, async (_req, res) => {
  res.json(await db.activity(150));
});

// Request access. The app does NOT touch governance — it only records the request; an administrator
// grants the role through the quorum. Once granted, it shows up on /api/session on the next request.
app.post("/api/vault/request-access", authRequired, requireCsrf, rateLimit({ windowMs: 60 * 1000, max: 5 }), async (req, res) => {
  const roles = await rolesFor(req.user.id).catch(() => []);
  if (roles.includes(ROLE)) return res.json({ ok: true, alreadyHeld: true });
  await db.logActivity({ type: "access_request", actor: req.user.id, actorEmail: req.user.email, allowed: null, detail: { role: ROLE } });
  res.json({ ok: true, role: ROLE });
});

// SPA fallback for anything that is not an API route.
app.get(/^(?!\/api\/).*/, (_req, res) => res.sendFile(join(HERE, "public", "index.html")));

app.listen(PORT, () => console.log(`Vault on http://localhost:${PORT}  (role gate: ${ROLE}, secure cookies: ${COOKIE_SECURE})`));
