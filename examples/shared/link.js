/**
 * A drop-in "link a Tide identity" flow for any of the login examples.
 *
 * Mount it and it turns "connect a Tide account to the user who is already signed in" into one link.
 * Your login stays exactly where it is; this handles the enclave round trip and hands you back the
 * vuid to store against your user.
 *
 *   import { link } from "../shared/link.js";
 *   app.use(link({
 *     resolveUser: (req) => currentUser(req),               // your signed-in user (needs .id), or null
 *     storeVuid:   (userId, vuid) => db.setVuid(userId, vuid),
 *     appUrl:      process.env.APP_URL,                      // must be the address minidauth signed
 *   }));
 *   // then link to /tide/link from your account page
 *
 * Two routes get added under `mount` (default `/tide`):
 *   GET /tide/link      start a sign-in for the signed-in user and redirect to the enclave
 *   GET /tide/callback  finish it, verify it, and store the vuid
 *
 * Security, the part that matters: the sign-in in flight is pinned to a short-lived, httpOnly cookie
 * this sets when the *already-signed-in* user starts it, and remembered against that user. The enclave
 * comes back by a top-level navigation carrying no session id of its own, so this cookie is what says
 * "this reply belongs to the link this user started", and one account's reply can never be applied to
 * another. Pinning it to a cookie rather than to the app's own session also means it works with login
 * providers that cannot identify the caller on the return navigation (a Clerk dev instance, say).
 *
 * If you need to do more than store a vuid (mutate your session object, best-effort persist, set a
 * flag) pass `onLinked({ req, userId, user, vuid, doken, roles })` instead of `storeVuid`.
 *
 * The callback address (`<appUrl><mount>/callback`) has to be a redirect URI minidauth has signed, or
 * the enclave will not return to it. Register it once (see docs/running.md).
 *
 * Dependency-free, so it works with any Express app whether or not a body parser is mounted ahead.
 */
import crypto from "node:crypto";
import { loginUrl, completeLogin } from "./minidauth.js";

const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

export function link({ resolveUser, storeVuid, onLinked, appUrl, mount = "/tide", cookie = "tide_link", afterLink } = {}) {
  if (typeof resolveUser !== "function") throw new Error("link: resolveUser(req) is required");
  if (typeof storeVuid !== "function" && typeof onLinked !== "function")
    throw new Error("link: storeVuid(userId, vuid) or onLinked({ userId, vuid }) is required");

  const base = () => appUrl ?? process.env.APP_URL;
  const who = (req) => (async () => resolveUser(req))().catch(() => null); // tolerate sync or async, throw or null
  const pending = new Map(); // linkId -> { sessionId, userId, at }
  const TTL = 10 * 60 * 1000;
  const sweep = () => { const now = Date.now(); for (const [k, v] of pending) if (now - v.at > TTL) pending.delete(k); };

  const readCookie = (req) => req.cookies?.[cookie]
    ?? (req.headers.cookie || "").split(/;\s*/).map((c) => c.split("=")).find(([k]) => k === cookie)?.[1];
  const setCookie = (res, value, maxAge) =>
    res.setHeader("Set-Cookie", `${cookie}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
  const query = (req, key) => req.query?.[key] ?? new URL(req.url, "http://x").searchParams.get(key);

  const redirect = (res, loc) => { res.statusCode = 302; res.setHeader("Location", loc); res.end(); };
  const html = (res, code, body) => {
    res.statusCode = code;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!doctype html><meta charset="utf-8"><body style="font:16px system-ui,-apple-system,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.55">${body}</body>`);
  };

  return async (req, res, next) => {
    const path = req.path || req.url.split("?")[0];
    if (path !== mount + "/link" && path !== mount + "/callback") return next();
    try {
      // Start: send the signed-in user off to the enclave, pinning the attempt to a cookie.
      if (req.method === "GET" && path === mount + "/link") {
        const user = await who(req);
        if (!user) return redirect(res, "/");
        if (!base()) return html(res, 500, "<h1>Not configured</h1><p>Set <code>appUrl</code> (or <code>APP_URL</code>) so the callback address is known.</p>");
        sweep();
        const sessionId = "app-" + crypto.randomUUID();
        const linkId = crypto.randomUUID();
        pending.set(linkId, { sessionId, userId: user.id, at: Date.now() });
        try {
          const url = await loginUrl(sessionId, base() + mount + "/callback");
          setCookie(res, linkId, 600);
          return redirect(res, url);
        } catch (e) {
          return html(res, 502, `<h1>Could not start the sign-in</h1><p>${esc(e.message)}</p>`);
        }
      }
      // Finish: the cookie names the attempt; the vuid is applied to the user who started it.
      const linkId = readCookie(req);
      const started = linkId ? pending.get(linkId) : null;
      if (linkId) { pending.delete(linkId); setCookie(res, "", 0); }
      const data = query(req, "vendorEncryptedData");
      if (!data || !started) return html(res, 400, "<h1>Not a sign-in this app started</h1><p>Start again from your account page.</p>");
      // If the provider can still identify the caller, it must be the same user; if it cannot, the
      // cookie is authority enough.
      const now = await who(req);
      if (now && String(now.id) !== String(started.userId)) return html(res, 400, "<h1>Signed in as someone else</h1><p>Start the link again.</p>");
      try {
        const { vuid, doken, roles } = await completeLogin(String(data), started.sessionId);
        if (onLinked) await onLinked({ req, userId: started.userId, user: now, vuid, doken, roles });
        else await storeVuid(started.userId, vuid);
        if (afterLink) return redirect(res, afterLink);
        return html(res, 200, `<h1>Linked</h1>
          <p>Tide identity <code>${esc(vuid.slice(0, 16))}…</code> is now on this account.</p>
          <p>If your app's session was issued before the link, sign in again to pick it up.</p>
          <p><a href="/">Back</a></p>`);
      } catch (e) {
        return html(res, 502, `<h1>Sign-in could not be verified</h1><p>${esc(e.message)}</p>`);
      }
    } catch (e) {
      return html(res, 502, `<h1>Error</h1><p>${esc(e.message)}</p>`);
    }
  };
}
