import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import * as cognito from "./cognito.js";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";

const app = express();
const PORT = process.env.PORT ?? 3001;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;

app.use(cookieParser());
app.use(express.json());

/* Two short-lived maps, both for one redirect each.
 *
 * `sessions` stands in for whatever session store the app already has. `pending` remembers which
 * signed-in account started a Tide link, so the enclave's reply can only attach to that account. */
const sessions = new Map();
const pending = new Map();

const current = (req) => sessions.get(req.cookies.sid);

const page = (body) => `<!doctype html><meta charset="utf-8">
<style>
  body{font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#ece9e2;color:#0e0e0c;
       margin:0;padding:40px;max-width:760px}
  a,button{font:inherit;border:2px solid #0e0e0c;background:#ece9e2;padding:8px 12px;cursor:pointer;
           text-decoration:none;color:inherit;display:inline-block;box-shadow:3px 3px 0 #0e0e0c}
  code{background:#dedbd4;padding:1px 4px}
  .pill{border:2px solid #0e0e0c;padding:1px 8px;font-size:13px}
  .no{color:#d6371c}
</style>${body}`;

app.get("/", async (req, res) => {
  const missing = cognito.missingConfig();
  if (missing.length) {
    return res.send(page(`<h1>Not configured yet</h1>
      <p>Set these and restart: ${missing.map((m) => `<code>${m}</code>`).join(", ")}</p>
      <p>See the README in this folder for what to create in Cognito.</p>`));
  }

  const s = current(req);
  if (!s) {
    return res.send(page(`<h1>minidauth + Cognito</h1>
      <p>Cognito owns the login. minidauth never sees a password, and the Cognito token never
      carries a role.</p>
      <p><a href="/login">Sign in with Cognito</a></p>`));
  }

  const roles = s.vuid ? await rolesFor(s.vuid).catch(() => []) : [];
  res.send(page(`<h1>${s.email ?? s.username}</h1>
    <p>Cognito subject <code>${s.sub}</code></p>
    <p>Tide identity ${s.vuid
      ? `<code>${s.vuid.slice(0, 16)}…</code>`
      : '<span class="no">not linked</span>'}</p>
    <p>Granted ${roles.length
      ? roles.map((r) => `<span class="pill">${r}</span>`).join(" ")
      : '<span class="no">nothing</span>'}</p>
    ${s.vuid ? "" : '<p><a href="/tide/link">Link a Tide identity</a></p>'}
    <p><a href="/protected">Open the protected page</a></p>`));
});

app.get("/login", (req, res) => {
  const state = crypto.randomUUID();
  pending.set(state, { at: Date.now() });
  res.redirect(cognito.authorizeUrl(`${APP_URL}/callback`, state));
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || !pending.delete(String(state))) {
    return res.status(400).send(page("<h1>Not a sign-in this app started</h1>"));
  }
  try {
    const claims = await cognito.exchangeCode(String(code), `${APP_URL}/callback`);
    const sid = crypto.randomUUID();
    sessions.set(sid, {
      sub: claims.sub,
      username: claims["cognito:username"] ?? claims.sub,
      email: claims.email,
      // Read back from the pool, so a returning user keeps their link.
      vuid: claims["custom:tide_vuid"] ?? null,
    });
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Cognito sign-in failed</h1><p>${e.message}</p>`));
  }
});

/* Link a Tide identity to the account that is already signed in. */
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
    await cognito.storeVuid(s.username, vuid);
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Sign-in could not be verified</h1><p>${e.message}</p>`));
  }
});

/* Authentication is Cognito's answer. Authorisation is not.
 *
 * The roles come from minidauth's grant record on every request. Nothing in the Cognito token is
 * consulted for them, on purpose: a role that arrives in a token your AWS account can mint is a
 * role your AWS account can grant itself. */
app.get("/protected", async (req, res) => {
  const s = current(req);
  if (!s?.vuid) return res.redirect("/");

  const roles = await rolesFor(s.vuid).catch(() => []);
  if (!roles.includes("vault-reader")) {
    return res.status(403).send(page(`<h1 class="no">Refused</h1>
      <p>This identity does not hold <code>vault-reader</code>. Granting it takes a quorum in the
      minidauth console. No change in Cognito will do it.</p>
      <p><a href="/">Back</a></p>`));
  }
  res.send(page(`<h1>Allowed</h1>
    <p>Held roles: ${roles.map((r) => `<span class="pill">${r}</span>`).join(" ")}</p>
    <p><a href="/">Back</a></p>`));
});

app.listen(PORT, () => console.log(`example on ${APP_URL}`));
