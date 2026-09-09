import express from "express";
import crypto from "node:crypto";
import { toNodeHandler, fromNodeHeaders } from "better-auth/node";
import { auth } from "./auth.js";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";

const app = express();
const PORT = process.env.PORT ?? 3000;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;

// Better Auth handles its own routes. Mounted before the body parser, which it does not want.
app.all("/api/auth/*", toNodeHandler(auth));
app.use(express.json());

/* Sign-ins in flight, by the id the enclave echoes back.
 *
 * In memory because they live for one redirect. Each one remembers which logged-in account started
 * the link, so the reply can only ever attach to that account. */
const pending = new Map();

const session = (req) => auth.api.getSession({ headers: fromNodeHeaders(req.headers) });

const page = (body) => `<!doctype html><meta charset="utf-8">
<style>
  body{font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;background:#ece9e2;color:#0e0e0c;
       margin:0;padding:40px;max-width:720px}
  a,button{font:inherit;border:2px solid #0e0e0c;background:#ece9e2;padding:8px 12px;cursor:pointer;
           text-decoration:none;color:inherit;display:inline-block;box-shadow:3px 3px 0 #0e0e0c}
  code{background:#dedbd4;padding:1px 4px}
  .pill{border:2px solid #0e0e0c;padding:1px 8px;font-size:13px}
  .no{color:#d6371c}
</style>${body}`;

app.get("/", async (req, res) => {
  const s = await session(req);
  if (!s) {
    return res.send(page(`<h1>minidauth + Better Auth</h1>
      <p>Sign in with Better Auth first. It owns accounts and sessions; minidauth never sees a
      password.</p>
      <form method="post" action="/signup">
        <p><input name="email" placeholder="email" value="demo@example.com">
        <input name="password" type="password" placeholder="password" value="password1234"></p>
        <button>Create account or sign in</button>
      </form>`));
  }

  const vuid = s.user.tideVuid;
  const roles = vuid ? await rolesFor(vuid).catch(() => []) : [];
  const canRead = roles.includes("vault-reader");

  res.send(page(`<h1>${s.user.email}</h1>
    <p>Better Auth account <code>${s.user.id}</code></p>
    <p>Tide identity ${vuid
      ? `<code>${vuid.slice(0, 16)}…</code>`
      : '<span class="no">not linked</span>'}</p>
    <p>Granted ${roles.length
      ? roles.map((r) => `<span class="pill">${r}</span>`).join(" ")
      : '<span class="no">nothing</span>'}</p>
    ${vuid ? "" : '<p><a href="/tide/link">Link a Tide identity</a></p>'}
    <p><a href="/protected">Open the protected page</a>
       ${canRead ? "" : '<span class="no">(you do not hold vault-reader)</span>'}</p>`));
});

app.post("/signup", express.urlencoded({ extended: false }), async (req, res) => {
  const { email, password } = req.body;
  const body = { email, password, name: email };
  // Same demo button for both, so the example does not need two forms to make its point.
  const result = await auth.api
    .signUpEmail({ body, asResponse: true })
    .catch(() => auth.api.signInEmail({ body: { email, password }, asResponse: true }));
  res.setHeader("set-cookie", result.headers.getSetCookie());
  res.redirect("/");
});

/* Start the link. The browser goes to the enclave, not to us and not to minidauth. */
app.get("/tide/link", async (req, res) => {
  const s = await session(req);
  if (!s) return res.redirect("/");

  const sessionId = "app-" + crypto.randomUUID();
  pending.set(s.user.id, { sessionId, at: Date.now() });
  try {
    res.redirect(await loginUrl(sessionId, `${APP_URL}/tide/callback`));
  } catch (e) {
    res.status(502).send(page(`<h1>Could not start the sign-in</h1><p>${e.message}</p>`));
  }
});

/* The enclave comes back here.
 *
 * The proof is verified by minidauth, so the vuid is proven rather than claimed. What this app
 * still has to get right is that the reply belongs to the sign-in it started, for the account that
 * started it, which is what the pending map is for. */
app.get("/tide/callback", async (req, res) => {
  // The enclave calls it vendorEncryptedData, and sends back no session id of its own.
  const data = req.query.vendorEncryptedData;
  const s = await session(req);
  const started = s ? pending.get(s.user.id) : null;
  if (s) pending.delete(s.user.id);

  if (!data || !started) {
    return res.status(400).send(page("<h1>Not a sign-in this app started</h1>"));
  }

  try {
    const { vuid } = await completeLogin(String(data), started.sessionId);
    await auth.api.updateUser({
      body: { tideVuid: vuid },
      headers: fromNodeHeaders(req.headers),
    });
    res.redirect("/");
  } catch (e) {
    res.status(502).send(page(`<h1>Sign-in could not be verified</h1><p>${e.message}</p>`));
  }
});

/* The whole point, in one route.
 *
 * Authentication is Better Auth's answer. Authorisation is not: it comes from the grant record,
 * which only a quorum can change. Nothing this app writes to its own database can put a role here.
 */
app.get("/protected", async (req, res) => {
  const s = await session(req);
  if (!s?.user.tideVuid) return res.redirect("/");

  const roles = await rolesFor(s.user.tideVuid).catch(() => []);
  if (!roles.includes("vault-reader")) {
    return res.status(403).send(page(`<h1 class="no">Refused</h1>
      <p>This identity does not hold <code>vault-reader</code>. Granting it takes a quorum, in the
      minidauth console. Editing this app's database will not do it.</p>
      <p><a href="/">Back</a></p>`));
  }
  res.send(page(`<h1>Allowed</h1>
    <p>Held roles: ${roles.map((r) => `<span class="pill">${r}</span>`).join(" ")}</p>
    <p><a href="/">Back</a></p>`));
});

app.listen(PORT, () => console.log(`example on ${APP_URL}`));
