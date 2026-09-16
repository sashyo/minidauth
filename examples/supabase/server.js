import express from "express";
import cookieParser from "cookie-parser";
import * as supabase from "./supabase.js";
import { rolesFor } from "../shared/minidauth.js";
import { tideless } from "../shared/tideless.js";
import { link } from "../shared/link.js";
import { page, identityBlock } from "../shared/page.js";

const app = express();
const PORT = process.env.PORT ?? 3004;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;

app.use(cookieParser());
app.use(express.json());

/* Supabase signs in from the browser, so the access token arrives in a cookie this app sets from
 * the client rather than in a session it created itself. */
const userOf = (req) => supabase.userFor(req.cookies.sb).catch(() => null);
// A tideless page: the signed-in user encrypts and decrypts with no Tide account (see ../shared/tideless.js).
app.use(tideless({ resolveUid: async (req) => (await userOf(req))?.id, role: "vault-reader" }));
// Linking a Tide identity to the signed-in user: one mount handles the enclave round trip and hands
// back the vuid to store (see ../shared/link.js). Adds GET /tide/link and GET /tide/callback.
app.use(link({ resolveUser: userOf, storeVuid: (id, vuid) => supabase.storeVuid(id, vuid), appUrl: APP_URL }));

app.get("/", async (req, res) => {
  const missing = supabase.missingConfig();
  if (missing.length) {
    return res.send(page(`<h1>Not configured yet</h1>
      <p>Set these and restart: ${missing.map((m) => `<code>${m}</code>`).join(", ")}</p>
      <p>See the README in this folder.</p>`));
  }

  const user = await userOf(req);
  const { url, anonKey } = supabase.publicConfig();
  if (!user) {
    // Supabase's own client does the sign-in; this app only keeps the resulting token.
    return res.send(page(`<h1>minidauth + Supabase</h1>
      <p>Supabase owns the login. minidauth never sees a password, and no role is ever read from
      the Supabase token.</p>
      <p><input id="email" placeholder="email"> <input id="password" type="password"
         placeholder="password"> <button id="go">Sign up or sign in</button></p>
      <pre id="out"></pre>
      <script type="module">
        import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
        const sb = createClient(${JSON.stringify(url)}, ${JSON.stringify(anonKey)});
        document.getElementById("go").onclick = async () => {
          const email = document.getElementById("email").value;
          const password = document.getElementById("password").value;
          let { data, error } = await sb.auth.signInWithPassword({ email, password });
          if (error) ({ data, error } = await sb.auth.signUp({ email, password }));
          if (error) { document.getElementById("out").textContent = error.message; return; }
          if (!data.session) {
            document.getElementById("out").textContent =
              "Check your email to confirm, or turn confirmations off in Supabase.";
            return;
          }
          document.cookie = "sb=" + data.session.access_token + "; path=/; samesite=lax";
          location.reload();
        };
      </script>`));
  }

  const roles = user.vuid ? await rolesFor(user.vuid).catch(() => []) : [];
  res.send(page(`<h1>${user.email ?? user.id}</h1>
    <p>Supabase user <code>${user.id}</code></p>
    ${identityBlock(user.vuid, roles)}
    ${user.vuid ? "" : '<p><a href="/tide/link">Link a Tide identity</a></p>'}
    <p><a href="/protected">Open the protected page</a></p>`));
});

app.get("/logout", (req, res) => {
  res.clearCookie("sb");
  res.redirect("/");
});

/* Authentication is Supabase's answer. Authorisation is not.
 *
 * Supabase copies app_metadata into the access token, so it would be easy to put roles there and
 * read them from the JWT. That is the mistake: a role in a token this project can mint is a role
 * this project can grant itself. */
app.get("/protected", async (req, res) => {
  const user = await userOf(req);
  if (!user?.vuid) return res.redirect("/");

  const roles = await rolesFor(user.vuid).catch(() => []);
  if (!roles.includes("vault-reader")) {
    return res.status(403).send(page(`<h1 class="no">Refused</h1>
      <p>This identity does not hold <code>vault-reader</code>. Granting it takes a quorum in the
      minidauth console. Editing this row in Supabase will not do it.</p>
      <p><a href="/">Back</a></p>`));
  }
  res.send(page(`<h1>Allowed</h1>
    <p>Held roles: ${roles.map((r) => `<span class="pill">${r}</span>`).join(" ")}</p>
    <p><a href="/">Back</a></p>`));
});

app.listen(PORT, () => console.log(`example on ${APP_URL}`));
