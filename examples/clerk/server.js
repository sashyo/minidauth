import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import * as clerk from "./clerk.js";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";
import { page, identityBlock } from "../shared/page.js";

const app = express();
const PORT = process.env.PORT ?? 3003;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;

app.use(cookieParser());

/* Tide sign-ins in flight, keyed by a cookie this app sets rather than by Clerk's session.
 *
 * The enclave returns by a cross site navigation, and a Clerk development instance cannot identify
 * the caller on one: its dev browser token is not carried, and authenticateRequest answers
 * "dev-browser-missing". Relying on the login provider to say who is returning is the fragile part
 * of any of these integrations, so this remembers it in a cookie of its own instead. */
const pending = new Map();

const LINK_COOKIE = "tide_link";

app.get("/", async (req, res) => {
  const missing = clerk.missingConfig();
  if (missing.length) {
    return res.send(page(`<h1>Not configured yet</h1>
      <p>Set these and restart: ${missing.map((m) => `<code>${m}</code>`).join(", ")}</p>
      <p>See the README in this folder.</p>`));
  }

  const user = await clerk.currentUser(req).catch(() => null);
  if (!user) {
    // Clerk's own component handles the sign-in, so this app has no login form of its own.
    return res.send(page(`<h1>minidauth + Clerk</h1>
      <p>Clerk owns the login. minidauth never sees a password, and the Clerk session token never
      carries a role.</p>
      <div id="signin"></div>
      <script async crossorigin="anonymous"
        data-clerk-publishable-key="${clerk.publishableKey()}"
        src="https://cdn.jsdelivr.net/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
        type="text/javascript"></script>
      <script>
        window.addEventListener("load", async () => {
          await window.Clerk.load();
          window.Clerk.mountSignIn(document.getElementById("signin"));
        });
      </script>`));
  }

  const roles = user.vuid ? await rolesFor(user.vuid).catch(() => []) : [];
  res.send(page(`<h1>${user.email ?? user.id}</h1>
    <p>Clerk user <code>${user.id}</code></p>
    ${identityBlock(user.vuid, roles)}
    ${user.vuid ? "" : '<p><a href="/tide/link">Link a Tide identity</a></p>'}
    <p><a href="/protected">Open the protected page</a></p>`));
});

app.get("/tide/link", async (req, res) => {
  const user = await clerk.currentUser(req).catch(() => null);
  if (!user) return res.redirect("/");

  const sessionId = "app-" + crypto.randomUUID();
  const linkId = crypto.randomUUID();
  pending.set(linkId, { sessionId, userId: user.id, at: Date.now() });
  try {
    const url = await loginUrl(sessionId, `${APP_URL}/tide/callback`);
    // Lax, so it survives the top level navigation back from the enclave and nothing else.
    res.cookie(LINK_COOKIE, linkId, { httpOnly: true, sameSite: "lax", maxAge: 10 * 60 * 1000 });
    res.redirect(url);
  } catch (e) {
    res.status(502).send(page(`<h1>Could not start the sign-in</h1><p>${e.message}</p>`));
  }
});

app.get("/tide/callback", async (req, res) => {
  // The enclave calls it vendorEncryptedData, and sends back no session id of its own.
  const data = req.query.vendorEncryptedData;
  const linkId = req.cookies[LINK_COOKIE];
  const started = linkId ? pending.get(linkId) : null;
  if (linkId) pending.delete(linkId);
  res.clearCookie(LINK_COOKIE);

  if (!data || !started) {
    return res.status(400).send(page("<h1>Not a sign-in this app started</h1>"));
  }
  try {
    const { vuid } = await completeLogin(String(data), started.sessionId);
    await clerk.storeVuid(started.userId, vuid);
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Sign-in could not be verified</h1><p>${e.message}</p>`));
  }
});

/* Authentication is Clerk's answer. Authorisation is not. */
app.get("/protected", async (req, res) => {
  const user = await clerk.currentUser(req).catch(() => null);
  if (!user?.vuid) return res.redirect("/");

  const roles = await rolesFor(user.vuid).catch(() => []);
  if (!roles.includes("vault-reader")) {
    return res.status(403).send(page(`<h1 class="no">Refused</h1>
      <p>This identity does not hold <code>vault-reader</code>. Granting it takes a quorum in the
      minidauth console. Editing this user's metadata will not do it.</p>
      <p><a href="/">Back</a></p>`));
  }
  res.send(page(`<h1>Allowed</h1>
    <p>Held roles: ${roles.map((r) => `<span class="pill">${r}</span>`).join(" ")}</p>
    <p><a href="/">Back</a></p>`));
});

app.listen(PORT, () => console.log(`example on ${APP_URL}`));
