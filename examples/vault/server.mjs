// Vault — server.
//
// Supabase owns the login. minidauth holds the vendor key and issues the vouchers that let the
// signed-in user's browser encrypt and decrypt with no Tide account (tideless). This server:
//   - resolves the Supabase user from a cookie the browser sets,
//   - proxies the two vouchers to minidauth, gating the decrypt voucher on the user's role,
//   - stores records (ciphertext only) and signed releases in Supabase.
//
// Run with no Supabase configured and it still serves the UI in demo mode.

import express from "express";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as db from "./db.mjs";
import { vaultConfig, signVoucher, decryptVoucher, rolesFor } from "../shared/minidauth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT ?? 3007;
const ROLE = process.env.VAULT_ROLE ?? "vault-reader";

app.use(cookieParser());
app.use(express.json({ limit: "512kb" }));
app.use(express.static(join(HERE, "public")));

const userOf = (req) => db.userFor(req.cookies.sb).catch(() => null);

// Who is signed in, and what roles their id holds (read live from minidauth on every request).
app.get("/api/session", async (req, res) => {
  const u = await userOf(req);
  if (!u) return res.status(401).json({ error: "not signed in" });
  const roles = await rolesFor(u.id).catch(() => []);
  res.json({ user: u.email ?? u.id, uid: u.id, roles });
});

// Public config + policy bytes the browser needs to reach the network.
app.get("/api/vault/config", async (_req, res) => {
  try { res.json(await vaultConfig()); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// Encrypt voucher (vendorsign) — any signed-in user may seal a field.
app.post("/api/vault/voucher/sign", async (req, res) => {
  if (!(await userOf(req))) return res.status(401).json({ error: "sign in first" });
  try { res.type("application/json").send(await signVoucher(req.body.voucherRequest)); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// Decrypt voucher (vendordecrypt) — gated on the user's id holding the role. The uid is taken from
// the verified session here, never from the browser.
app.post("/api/vault/voucher/decrypt", async (req, res) => {
  const u = await userOf(req);
  if (!u) return res.status(401).json({ error: "sign in first" });
  try { res.type("application/json").send(await decryptVoucher(u.id, ROLE, req.body.voucherRequest)); }
  catch (e) { res.status(403).json({ error: "the network declined — " + String(e.message || e) }); }
});

// Records — ciphertext in, ciphertext out. The plaintext only ever exists in a browser.
app.get("/api/vault/records", async (req, res) => {
  if (!(await userOf(req))) return res.status(401).json({ error: "sign in first" });
  try { res.json(await db.records()); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});
app.post("/api/vault/records", async (req, res) => {
  const u = await userOf(req);
  if (!u) return res.status(401).json({ error: "sign in first" });
  const { name, ref, ct } = req.body ?? {};
  if (!name) return res.status(400).json({ error: "name is required" });
  try { res.json(await db.addRecord({ name, ref, ct: ct ?? {}, by: u.id })); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

// A signed release. The instruction is signed by the cohort under the payment policy, which reads
// the amount and refuses over the limit; the server verifies the signature before storing "signed".
app.post("/api/vault/release", async (req, res) => {
  const u = await userOf(req);
  if (!u) return res.status(401).json({ error: "sign in first" });
  try { res.json(await db.recordRelease({ ...req.body, by: u.id })); }
  catch (e) { res.status(400).json({ error: String(e.message || e) }); }
});

app.listen(PORT, () => console.log(`Vault on http://localhost:${PORT}  (role gate: ${ROLE})`));
