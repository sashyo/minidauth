/**
 * Tell minidauth about an app's Tide callback.
 *
 * The enclave will not return to a URI minidauth has not signed, and the failure arrives late and
 * unhelpfully, so every example registers itself rather than leaving it to a step you might skip.
 *
 * Merges rather than replaces. The settings endpoint takes the whole list, so writing only your own
 * URI would silently unsign the console and every other app.
 *
 *   MINIDAUTH_OPS_TOKEN=<token> APP_URL=http://localhost:3002 node ../shared/register-callback.js
 */
const MINIDAUTH_URL = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const APP_URL = process.env.APP_URL;
const OPS = process.env.MINIDAUTH_OPS_TOKEN;

if (!APP_URL || !OPS) {
  console.error("Set APP_URL and MINIDAUTH_OPS_TOKEN.");
  process.exit(1);
}

const headers = { "Content-Type": "application/json", Authorization: "Bearer " + OPS };
const cfg = await fetch(`${MINIDAUTH_URL}/tide/enclave/config`, { headers }).then((r) => r.json());

const redirectUris = [...new Set([...(cfg.signedRedirectUris ?? []), `${APP_URL}/tide/callback`])];
const clientOrigins = [...new Set([...(cfg.signedClientOrigins ?? []), new URL(APP_URL).origin])];
const settings = JSON.parse(cfg.signedSettings ?? "{}");

const res = await fetch(`${MINIDAUTH_URL}/tide/enclave/settings`, {
  method: "POST",
  headers,
  body: JSON.stringify({
    regOn: settings.RegOn ?? true,
    backupOn: settings.BackupOn ?? false,
    logoUrl: settings.LogoURL ?? "https://tide.org/favicon.ico",
    imageUrl: settings.ImageURL ?? "https://tide.org/favicon.ico",
    redirectUris,
    clientOrigins,
  }),
});
if (!res.ok) {
  console.error("minidauth refused the settings:", await res.text());
  process.exit(1);
}
console.log("registered", `${APP_URL}/tide/callback`);
console.log("signed redirect URIs are now:", redirectUris.join(", "));
