// One-shot sealing bootstrap. After `docker compose --profile seal up` and creating a vendor key,
// this deploys the standard vault policies and grants a demo reader role, so an app can seal and
// open straight away. Idempotent: it detects what is already in place and does only the rest.
//
//   node bootstrap/bootstrap.mjs
//
// Config (all optional):
//   MINIDAUTH_URL     minidauth base URL           default http://localhost:8081
//   OPERATORS_FILE    operators.json path          default ./operators.json
//   READER_ROLE       the role a reader must hold   default crm-reader
//   DEMO_UID          app user id to grant it to    default 1   (empty to skip the grant)
//
// The one thing it cannot do is create the vendor key: that needs a Tide licence and, for a real
// sign-in, a browser. See docs/running.md. This script refuses to proceed until the key exists.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const MC = (process.env.MINIDAUTH_URL ?? "http://localhost:8081").replace(/\/$/, "");
const OPERATORS_FILE = process.env.OPERATORS_FILE ?? resolve(HERE, "..", "operators.json");
const READER_ROLE = process.env.READER_ROLE ?? "crm-reader";
const DEMO_UID = process.env.DEMO_UID ?? "1";

const ops = JSON.parse(readFileSync(OPERATORS_FILE, "utf8"));
const tok = (roleOrName) => {
  const byRole = ops.find((o) => (o.roles ?? []).includes(roleOrName) && o.token);
  const byName = ops.find((o) => o.name === roleOrName && o.token);
  return (byRole ?? byName)?.token;
};
const OPS = tok("vrk-admin");
const APPROVERS = ops.filter((o) => (o.roles ?? []).includes("approver") && o.token).map((o) => o.token);
if (!OPS) throw new Error(`no vrk-admin token in ${OPERATORS_FILE}`);
if (APPROVERS.length < 2) throw new Error(`need at least 2 approver tokens in ${OPERATORS_FILE}`);

const api = async (path, { method = "GET", token = OPS, body } = {}) => {
  const r = await fetch(MC + path, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json; try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text }; }
  return { status: r.status, json, location: r.headers.get("location") };
};

// File a change request, gather approvals, commit. The single choke point for every governed change
// here: a contract registration, a policy deployment, or a role grant. Filing must be done by an
// approver (the quorum), not the vrk-admin token; the other approvers then authorize, and the
// vrk-admin commits. This is the whole point: no one operator can make a change alone.
const governedChange = async (path, body) => {
  const filer = APPROVERS[0];
  const filed = await api(path, { method: "POST", token: filer, body });
  if (filed.status >= 400) throw new Error(`${path} -> ${filed.status} ${JSON.stringify(filed.json)}`);
  const id = filed.json.id ?? (filed.location ?? "").split("/").pop();
  for (const a of APPROVERS.slice(1, 3)) await api(`/iga/change-requests/${id}/authorize`, { method: "POST", token: a });
  let c = await api(`/iga/change-requests/${id}/commit`, { method: "POST", token: OPS });
  if (c.status >= 400) c = await api(`/iga/change-requests/${id}/commit`, { method: "POST", token: filer });
  if (c.status >= 400) throw new Error(`commit ${id} -> ${c.status} ${JSON.stringify(c.json)}`);
  return id;
};

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // 0. Wait for minidauth, then require a live vendor key.
  process.stdout.write(`bootstrap: minidauth at ${MC}\n`);
  for (let i = 0; i < 30; i++) {
    const s = await api("/vrk/state").catch(() => ({ status: 0 }));
    if (s.status === 200) break;
    if (i === 29) throw new Error(`minidauth not reachable at ${MC}`);
    await wait(2000);
  }
  const state = await api("/vrk/state");
  const st = state.json.state ?? state.json.vendorKeyState ?? JSON.stringify(state.json);
  if (!/created|active|live/i.test(String(st))) {
    console.error(`\nNo vendor key yet (state: ${st}). Create one first — it needs a Tide licence:\n`);
    console.error(`  curl -sX POST ${MC}/vrk/create -H "Authorization: Bearer <ops>" \\`);
    console.error(`    -H 'Content-Type: application/json' \\`);
    console.error(`    -d '{"licensingTier":"FreeTier","email":"you@example.com","redirectUrl":"${MC}/console"}'\n`);
    console.error("Call it again after paying to finalize, then re-run this script. See docs/running.md.");
    process.exit(2);
  }
  console.log(`bootstrap: vendor key ${st}`);

  // 1. Policies. Skip any already deployed (idempotent), deploy the rest in the required order:
  //    bootstrap first (it spends the authorizer pack), then encrypt, then decrypt.
  const CONTRACTS = {
    bootstrap: { name: "minidauth-bootstrap", file: "contracts/bootstrap.forseti" },
    vault: { name: "minidauth-vault", file: "contracts/vault.forseti" },
  };
  const POLICIES = [
    { model: "AttestationUnit:1", contract: "bootstrap", params: { purpose: "bootstrap" }, extraModel: "Policy:1" },
    { model: "PolicyEnabledEncryption:1", contract: "vault", params: { purpose: "vault-encrypt" } },
    { model: "PolicyEnabledDecryption:1", contract: "vault", params: { purpose: "vault-decrypt" } },
  ];
  const deployed = (await api("/iga/policies")).json;
  const have = new Set((Array.isArray(deployed) ? deployed : []).flatMap((p) => p.modelIds ?? []));
  const registered = new Set();
  for (const pol of POLICIES) {
    if (have.has(pol.model)) { console.log(`bootstrap: policy ${pol.model} already deployed, skipping`); continue; }
    // Register the contract once (the policy references it by id and uploadContract ships its source).
    if (!registered.has(pol.contract)) {
      const c = CONTRACTS[pol.contract];
      const source = readFileSync(resolve(HERE, c.file), "utf8");
      await governedChange("/iga/change-requests/contract", { name: c.name, source, type: "forseti" }).catch((e) => {
        if (!/already|exists|registered/i.test(String(e))) throw e; // fine if it was registered before
      });
      registered.add(pol.contract);
    }
    const source = readFileSync(resolve(HERE, CONTRACTS[pol.contract].file), "utf8");
    const modelIds = pol.extraModel ? [pol.model, pol.extraModel] : [pol.model];
    console.log(`bootstrap: deploying policy ${modelIds.join("+")}`);
    await governedChange("/iga/change-requests/policy", {
      source, uploadContract: true, modelIds,
      approvalType: "IMPLICIT", executionType: "PUBLIC", params: pol.params,
    });
  }

  // 2. Grant the demo reader role, so an app can open immediately. Tideless: keyed on an app user id.
  if (DEMO_UID) {
    const g = (await api(`/iga/grants/${encodeURIComponent(DEMO_UID)}`)).json;
    if ((g.roles ?? []).includes(READER_ROLE)) {
      console.log(`bootstrap: uid ${DEMO_UID} already holds ${READER_ROLE}`);
    } else {
      console.log(`bootstrap: granting ${READER_ROLE} to uid ${DEMO_UID}`);
      await governedChange("/iga/change-requests/role", { vuid: DEMO_UID, role: READER_ROLE, tideless: true });
    }
  }

  console.log(`\nSealing is ready. Point an app at the sidecar:\n`);
  console.log(`  MINIDAUTH_SEAL_URL=http://localhost:3021`);
  console.log(`  MINIDAUTH_SEAL_SIGNING_KEY_FILE=<this repo>/keys/usertoken.key`);
  console.log(`\nThe app signs reader tokens for its user ids; grant ${READER_ROLE} to a user and their sealed fields open.`);
}

main().catch((e) => { console.error("bootstrap failed:", e.message ?? e); process.exit(1); });
