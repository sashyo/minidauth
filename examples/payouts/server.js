import express from "express";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import * as db from "./db.js";
import { loginUrl, completeLogin, rolesFor } from "../shared/minidauth.js";
import { instructionFor, verifyInstruction } from "./verify.js";

const app = express();
const PORT = process.env.PORT ?? 3006;
const APP_URL = process.env.APP_URL ?? `http://localhost:${PORT}`;
const MINIDAUTH_URL = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const MINIDAUTH_TOKEN = process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";

app.use(cookieParser());
app.use(express.json());
app.use("/public", express.static("public"));
app.get("/", (req, res) => res.sendFile(process.cwd() + "/public/index.html"));

/* Two sign-ins, on purpose.
 *
 * Supabase says who you are to this app. Tide proves the identity the network will act for, and
 * hands the browser a token the enclave needs. The Tide session is bound to the Supabase user that
 * started it, so one account can never pick up another's. */
const tideSessions = new Map();
const pending = new Map();

const supabaseUser = (req) => db.userFor(req.cookies.sb).catch(() => null);

async function whoIs(req) {
  const user = await supabaseUser(req);
  if (!user) return null;
  const tide = tideSessions.get(req.cookies.tide);
  const unlocked = tide && tide.userId === user.id && tide.vuid === user.vuid ? tide : null;
  return { ...user, tide: unlocked };
}

const needUser = (fn) => async (req, res) => {
  const who = await whoIs(req);
  if (!who) return res.status(401).json({ error: "Sign in first" });
  try { await fn(req, res, who); } catch (e) { res.status(500).json({ error: e.message }); }
};

const needTide = (fn) => needUser((req, res, who) => who.tide
  ? fn(req, res, who)
  : res.status(401).json({ error: "Unlock with Tide first" }));

app.get("/api/config", async (req, res) => {
  const missing = db.missingConfig();
  if (missing.length) return res.json({ missing });
  res.json({ ...db.publicConfig(), schemaMissing: await db.schemaMissing().catch(() => false) });
});

/* Roles are read from minidauth on every call, never cached on the user. A revocation should stop
 * working when the quorum says so, not when somebody next signs in. */
app.get("/api/me", needUser(async (req, res, who) => {
  const roles = who.vuid ? await rolesFor(who.vuid).catch(() => []) : [];
  res.json({
    email: who.email,
    userId: who.id,
    vuid: who.vuid,
    unlocked: !!who.tide,
    doken: who.tide?.doken ?? null,
    roles,
    rolesAtUnlock: who.tide?.rolesAtUnlock ?? [],
  });
}));

app.get("/api/tide/start", needUser(async (req, res, who) => {
  const sessionId = "payouts-" + crypto.randomUUID();
  pending.set(who.id, { sessionId, at: Date.now() });
  res.json({ url: await loginUrl(sessionId, `${APP_URL}/tide/callback`) });
}));

app.get("/tide/callback", async (req, res) => {
  // The enclave returns its payload but not the session id, so this side remembers which sign-in
  // it started, and for whom.
  const data = req.query.vendorEncryptedData;
  const user = await supabaseUser(req);
  const started = user ? pending.get(user.id) : null;
  if (user) pending.delete(user.id);
  if (!data || !started || Date.now() - started.at > 600000) {
    return res.status(400).send("Not a sign-in this app started");
  }

  try {
    const { vuid, doken } = await completeLogin(String(data), started.sessionId);
    if (!user.vuid) {
      await db.storeVuid(user.id, vuid);
    } else if (user.vuid !== vuid) {
      return res.status(403).send("That Tide identity is not the one linked to this account");
    }
    const sid = crypto.randomUUID();
    // What the doken carries, roughly: the roles held at the moment it was minted. Kept so the page
    // can tell a role granted since then from one never held.
    const rolesAtUnlock = await rolesFor(vuid).catch(() => []);
    tideSessions.set(sid, { userId: user.id, vuid, doken, rolesAtUnlock });
    res.cookie("tide", sid, { httpOnly: true, sameSite: "lax" });
    // No need to sign in to Supabase again: userFor asks Supabase for the user as it is now, not as
    // the token remembers it.
    res.redirect("/");
  } catch (e) {
    res.status(502).send("Sign-in could not be verified: " + e.message);
  }
});

app.get("/api/logout", (req, res) => {
  tideSessions.delete(req.cookies.tide);
  res.clearCookie("tide");
  res.clearCookie("sb");
  res.json({ ok: true });
});

/* What the enclave needs to open, and the policies it acts under. All public by design: signed
 * settings, a signature over this origin, and policies the ORKs enforce whoever presents them. */
app.get("/api/enclave", needTide(async (req, res) => {
  const auth = { Authorization: "Bearer " + MINIDAUTH_TOKEN };
  const get = (p) => fetch(MINIDAUTH_URL + p, { headers: auth }).then((r) => r.json());
  const post = (p) => fetch(MINIDAUTH_URL + p, { method: "POST", headers: auth }).then((r) => r.json());

  const [cfg, origin, voucher, encrypt, decrypt, policies] = await Promise.all([
    get("/tide/enclave/config"),
    get("/tide/enclave/origin-signature?origin=" + encodeURIComponent(APP_URL)),
    post("/console/session/voucher-url"),
    get("/vault/encrypt-policy"),
    get("/vault/decrypt-policy").catch(() => null),
    get("/iga/policies").catch(() => []),
  ]);
  const list = Array.isArray(policies) ? policies : Object.values(policies ?? {});
  const payment = list.find((x) => (x.modelIds ?? []).some((m) => m.startsWith("BasicCustom<")));

  res.json({
    homeOrkUrl: cfg.homeOrkUrl,
    vvkId: cfg.vvkId,
    clientOriginAuth: origin.clientOriginAuth,
    voucherUrl: voucher.voucherUrl,
    encryptPolicy: encrypt.policy,
    decryptPolicy: decrypt?.policy ?? null,
    paymentPolicy: payment?.policyBytes ?? null,
    paymentModel: payment?.modelIds?.[0] ?? null,
    paymentLimit: payment?.params?.limit ?? null,
  });
}));

/* Payees. The server stores the bank details exactly as the enclave produced them and has no way to
 * read them back. There is no decrypt path in this file, and adding one would not help. */
app.get("/api/payees", needUser(async (req, res) => res.json(await db.payees())));

app.post("/api/payees", needTide(async (req, res, who) => {
  const { name, bankCiphertext } = req.body ?? {};
  if (!name || typeof bankCiphertext !== "string" || !bankCiphertext) {
    return res.status(400).json({ error: "name and bankCiphertext are required" });
  }
  res.json(await db.addPayee({
    name: String(name).slice(0, 80),
    bank_ciphertext: bankCiphertext,
    created_by: who.id,
  }));
}));

/* Payouts, each checked against the network's signature every time it is read.
 *
 * The status column is only this app's opinion. The signature is the network's, over an instruction
 * rebuilt from the row as it stands now, so editing the amount in Supabase turns a signed payout
 * into a forged one on the next page load. */
app.get("/api/payouts", needUser(async (req, res) => {
  const rows = await db.payouts();
  res.json(await Promise.all(rows.map(async (p) => ({
    ...p,
    check: p.status === "signed" ? await verifyInstruction(instructionFor(p), p.signature) : null,
  }))));
}));

app.post("/api/payouts", needTide(async (req, res, who) => {
  const amount = Number(req.body?.amount);
  const payeeId = String(req.body?.payeeId ?? "");
  if (!Number.isInteger(amount) || amount <= 0 || !payeeId) {
    return res.status(400).json({ error: "a payee and a whole, positive amount are required" });
  }
  const row = await db.addPayout({ payee_id: payeeId, amount, requested_by: who.id });
  res.json(await db.updatePayout(row.id, { instruction: instructionFor(row) }));
}));

/* The browser reports what the network answered. A refusal is taken at its word, since a false one
 * costs nothing. A signature is not: it is checked here before the row is allowed to say "signed". */
app.post("/api/payouts/:id/decision", needTide(async (req, res) => {
  const p = await db.payout(req.params.id);
  if (!p) return res.status(404).json({ error: "no such payout" });
  if (p.status !== "pending") return res.status(409).json({ error: "already decided" });

  const { signature, refusal } = req.body ?? {};
  if (signature) {
    const check = await verifyInstruction(instructionFor(p), signature);
    if (!check.valid) return res.status(400).json({ error: "signature does not verify: " + check.reason });
    return res.json(await db.updatePayout(p.id, {
      status: "signed", signature, decided_at: new Date().toISOString(),
    }));
  }
  res.json(await db.updatePayout(p.id, {
    status: "refused", refusal: String(refusal ?? "refused").slice(0, 300),
    decided_at: new Date().toISOString(),
  }));
}));

/* The tables exactly as the secret key returns them. This is the view somebody gets when that key
 * leaks, and it is shown so the claim can be checked rather than believed. */
app.get("/api/breach", needUser(async (req, res) => {
  res.json({ payees: await db.payees(), payouts: await db.payouts() });
}));

app.listen(PORT, () => console.log(`payouts on ${APP_URL}`));
