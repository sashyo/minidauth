import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import * as auth0 from "./auth0.js";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";
import { page, identityBlock } from "../shared/page.js";

const app = express();
const PORT = process.env.PORT ?? 3002;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;

app.use(cookieParser());

const sessions = new Map();
const pending = new Map();
const current = (req) => sessions.get(req.cookies.sid);

app.get("/", async (req, res) => {
  const missing = auth0.missingConfig();
  if (missing.length) {
    return res.send(page(`<h1>Not configured yet</h1>
      <p>Set these and restart: ${missing.map((m) => `<code>${m}</code>`).join(", ")}</p>
      <p>See the README in this folder.</p>`));
  }

  const s = current(req);
  if (!s) {
    return res.send(page(`<h1>minidauth + Auth0</h1>
      <p>Auth0 owns the login. minidauth never sees a password, and the Auth0 token never carries a
      role.</p>
      <p><a href="/login">Sign in with Auth0</a></p>`));
  }

  const roles = s.vuid ? await rolesFor(s.vuid).catch(() => []) : [];
  res.send(page(`<h1>${s.email ?? s.sub}</h1>
    <p>Auth0 subject <code>${s.sub}</code></p>
    ${identityBlock(s.vuid, roles)}
    ${s.vuid ? "" : '<p><a href="/tide/link">Link a Tide identity</a></p>'}
    ${s.vuid && s.persisted === false ? `<p class="no">Kept in this session only. Writing it to
      <code>app_metadata</code> needs this application authorised for the Management API with
      <code>update:users</code>.</p>` : ""}
    <p><a href="/protected">Open the protected page</a></p>`));
});

app.get("/login", (req, res) => {
  const state = crypto.randomUUID();
  pending.set(state, { at: Date.now() });
  res.redirect(auth0.authorizeUrl(`${APP_URL}/callback`, state));
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || !pending.delete(String(state))) {
    return res.status(400).send(page("<h1>Not a sign-in this app started</h1>"));
  }
  try {
    const claims = await auth0.exchangeCode(String(code), `${APP_URL}/callback`);
    const sid = crypto.randomUUID();
    sessions.set(sid, {
      sub: claims.sub,
      email: claims.email,
      // Set by an Auth0 Action if you add one, otherwise linked in this session.
      vuid: claims["https://minidauth/tide_vuid"] ?? null,
    });
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Auth0 sign-in failed</h1><p>${e.message}</p>`));
  }
});

app.get("/tide/link", async (req, res) => {
  const s = current(req);
  if (!s) return res.redirect("/");
  const sessionId = "app-" + crypto.randomUUID();
  pending.set(s.sub, { sessionId, at: Date.now() });
  try {
    res.redirect(await loginUrl(sessionId, `${APP_URL}/tide/callback`));
  } catch (e) {
    res.status(502).send(page(`<h1>Could not start the sign-in</h1><p>${e.message}</p>`));
  }
});

app.get("/tide/callback", async (req, res) => {
  // The enclave calls it vendorEncryptedData, and sends back no session id of its own.
  const data = req.query.vendorEncryptedData;
  const s = current(req);
  const started = s ? pending.get(s.sub) : null;
  if (s) pending.delete(s.sub);

  if (!data || !started) {
    return res.status(400).send(page("<h1>Not a sign-in this app started</h1>"));
  }
  try {
    const { vuid } = await completeLogin(String(data), started.sessionId);
    s.vuid = vuid;

    /* Persisting the link is best effort.
     *
     * Writing app_metadata needs this application authorised for the Management API with
     * update:users, which is a separate screen in the Auth0 dashboard and easy to miss. Without it
     * the demo still works, the link just lives in this session and is gone on restart. Better to
     * say so than to fail a sign-in over a permission the reader has not granted yet. */
    try {
      await auth0.storeVuid(s.sub, vuid);
      s.persisted = true;
    } catch (e) {
      s.persisted = false;
      s.persistError = e.message;
      console.log("could not persist the vuid to Auth0:", e.message);
    }
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Sign-in could not be verified</h1><p>${e.message}</p>`));
  }
});

/* Authentication is Auth0's answer. Authorisation is not. */
app.get("/protected", async (req, res) => {
  const s = current(req);
  if (!s?.vuid) return res.redirect("/");
  const roles = await rolesFor(s.vuid).catch(() => []);
  if (!roles.includes("vault-reader")) {
    return res.status(403).send(page(`<h1 class="no">Refused</h1>
      <p>This identity does not hold <code>vault-reader</code>. Granting it takes a quorum in the
      minidauth console. No Auth0 rule or Action will do it.</p>
      <p><a href="/">Back</a></p>`));
  }
  res.send(page(`<h1>Allowed</h1>
    <p>Held roles: ${roles.map((r) => `<span class="pill">${r}</span>`).join(" ")}</p>
    <p><a href="/">Back</a></p>`));
});

app.listen(PORT, () => console.log(`example on ${APP_URL}`));
