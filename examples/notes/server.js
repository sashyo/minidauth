import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import fs from "node:fs";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";

const app = express();
const PORT = process.env.PORT ?? 3005;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;
const STORE = "notes.json";

app.use(cookieParser());
app.use(express.json());

/* The whole database, such as it is.
 *
 * A file rather than Postgres on purpose: the claim being demonstrated is about what the storage
 * contains, and a file you can cat makes that checkable in one step. Point it at a real database
 * and nothing about the argument changes. */
const load = () => (fs.existsSync(STORE) ? JSON.parse(fs.readFileSync(STORE, "utf8")) : []);
const save = (notes) => fs.writeFileSync(STORE, JSON.stringify(notes, null, 2));

const sessions = new Map();
const pending = new Map();
const LINK_COOKIE = "tide_link";
const current = (req) => sessions.get(req.cookies.sid);

app.get("/", (req, res) => res.sendFile(process.cwd() + "/public/index.html"));
app.use("/public", express.static("public"));

/* Who is signed in, and what the network says they may do.
 *
 * The roles are read on every call rather than kept in the session, so a revocation takes effect
 * immediately rather than at next login. */
app.get("/api/me", async (req, res) => {
  const s = current(req);
  if (!s) return res.json({ signedIn: false });
  const roles = await rolesFor(s.vuid).catch(() => []);
  res.json({
    signedIn: true,
    vuid: s.vuid,
    roles,
    canRead: roles.includes("vault-reader"),
    canWrite: roles.includes("vault-writer"),
    doken: s.doken,
  });
});

app.get("/api/login-url", async (req, res) => {
  const sessionId = "notes-" + crypto.randomUUID();
  const linkId = crypto.randomUUID();
  pending.set(linkId, { sessionId, at: Date.now() });
  try {
    const url = await loginUrl(sessionId, `${APP_URL}/tide/callback`);
    res.cookie(LINK_COOKIE, linkId, { httpOnly: true, sameSite: "lax", maxAge: 600000 });
    res.json({ url });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get("/tide/callback", async (req, res) => {
  const data = req.query.vendorEncryptedData;
  const linkId = req.cookies[LINK_COOKIE];
  const started = linkId ? pending.get(linkId) : null;
  if (linkId) pending.delete(linkId);
  res.clearCookie(LINK_COOKIE);
  if (!data || !started) return res.status(400).send("Not a sign-in this app started");

  try {
    const { vuid, doken } = await completeLogin(String(data), started.sessionId);
    const sid = crypto.randomUUID();
    // The doken goes to the browser because the enclave needs it, and it is bound to a session key
    // that only that browser holds. It is useless anywhere else.
    sessions.set(sid, { vuid, doken });
    res.cookie("sid", sid, { httpOnly: true, sameSite: "lax" });
    res.redirect("/");
  } catch (e) {
    res.status(502).send("Sign-in could not be verified: " + e.message);
  }
});

app.get("/api/logout", (req, res) => {
  sessions.delete(req.cookies.sid);
  res.clearCookie("sid");
  res.json({ ok: true });
});

/* What the enclave needs to open, and the policies it will act under.
 *
 * All of it is public by design: signed settings, a signature over this origin, and a policy the
 * ORKs enforce regardless of who presents it. */
app.get("/api/enclave", async (req, res) => {
  const s = current(req);
  if (!s) return res.status(401).json({ error: "not signed in" });
  try {
    const base = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
    const auth = { Authorization: "Bearer " + (process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token") };
    const get = (p) => fetch(base + p, { headers: auth }).then((r) => r.json());
    const post = (p) => fetch(base + p, { method: "POST", headers: auth }).then((r) => r.json());

    const [cfg, origin, voucher, encrypt] = await Promise.all([
      get("/tide/enclave/config"),
      get("/tide/enclave/origin-signature?origin=" + encodeURIComponent(APP_URL)),
      post("/console/session/voucher-url"),
      fetch(base + "/vault/encrypt-policy").then((r) => r.json()),
    ]);
    const decrypt = await get("/vault/decrypt-policy").catch(() => null);

    res.json({
      homeOrkUrl: cfg.homeOrkUrl,
      vvkId: cfg.vvkId,
      clientOriginAuth: origin.clientOriginAuth,
      voucherUrl: voucher.voucherUrl,
      encryptPolicy: encrypt.policy,
      decryptPolicy: decrypt?.policy ?? null,
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

/* Storage. Neither route can read a note, and neither needs to.
 *
 * The ciphertext arrives already encrypted by the enclave and leaves exactly as it arrived. This
 * server has no way to turn it into anything, which is the point of the demo. */
app.get("/api/notes", (req, res) => {
  if (!current(req)) return res.status(401).json({ error: "not signed in" });
  res.json(load());
});

app.post("/api/notes", (req, res) => {
  const s = current(req);
  if (!s) return res.status(401).json({ error: "not signed in" });
  const { ciphertext, title } = req.body ?? {};
  if (typeof ciphertext !== "string" || !ciphertext) {
    return res.status(400).json({ error: "ciphertext is required" });
  }
  const notes = load();
  notes.unshift({
    id: crypto.randomUUID(),
    title: String(title ?? "untitled").slice(0, 80),
    author: s.vuid.slice(0, 16),
    ciphertext,
    createdAt: new Date().toISOString(),
  });
  save(notes);
  res.json({ ok: true });
});

/** The raw file, so the claim can be checked rather than believed. */
app.get("/api/raw", (req, res) => {
  if (!current(req)) return res.status(401).json({ error: "not signed in" });
  res.type("text/plain").send(fs.existsSync(STORE) ? fs.readFileSync(STORE, "utf8") : "[]");
});

app.listen(PORT, () => console.log(`notes demo on ${APP_URL}`));
