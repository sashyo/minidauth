/**
 * A drop-in tideless page for any of the login examples.
 *
 * Mount it on your Express app and it adds one page where the *currently signed-in user* — as your
 * own login already knows them — encrypts and decrypts with no Tide account and no doken. The app's
 * user id is the subject; a role a quorum granted that id is the gate.
 *
 *   import { tideless } from "../shared/tideless.js";
 *   app.use(tideless({ resolveUid: async (req) => (await currentUser(req))?.id, role: "vault-reader" }));
 *   // then link to /tideless
 *
 * The browser holds no credential. It gets vouchers and public policy bytes from the routes below;
 * the decrypt voucher is gated on the uid THIS server resolves from its own session, never on
 * anything the page sends, so a page cannot read as a user other than the one calling.
 *
 * Requires a minidauth whose decrypt policy is PUBLIC (voucher-gated), and the user's id granted the
 * role as a tideless subject. See examples/tideless for the round trip and docs/running.md for setup.
 *
 * Implemented as a plain middleware (no framework dependency), so it works with any Express app
 * whether or not a JSON body parser is mounted ahead of it.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { vaultConfig, signVoucher, decryptVoucher } from "./minidauth.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PAGE = readFileSync(join(HERE, "tideless.html"), "utf8");

function readJson(req) {
  return new Promise((resolve) => {
    if (req.body && typeof req.body === "object") return resolve(req.body); // a parser already ran
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch { resolve({}); } });
    req.on("error", () => resolve({}));
  });
}

export function tideless({ resolveUid, role = "vault-reader", mount = "/tideless" } = {}) {
  if (typeof resolveUid !== "function") throw new Error("tideless: resolveUid(req) is required");

  const json = (res, code, obj) => { res.statusCode = code; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(obj)); };
  const raw = (res, text) => { res.setHeader("Content-Type", "application/json"); res.end(text); };

  return async (req, res, next) => {
    const path = (req.path || req.url.split("?")[0]);
    if (path !== mount && !path.startsWith(mount + "/")) return next();
    const sub = path.slice(mount.length); // "", "/config", "/voucher/sign", "/voucher/decrypt"
    try {
      if (req.method === "GET" && (sub === "" || sub === "/")) {
        res.setHeader("Content-Type", "text/html; charset=utf-8"); return res.end(PAGE);
      }
      const uid = await resolveUid(req).catch(() => null);
      if (!uid) return json(res, 401, { error: "sign in first" });

      if (req.method === "GET" && sub === "/config") {
        return raw(res, JSON.stringify({ ...(await vaultConfig()), user: uid, role }));
      }
      // Encrypt voucher: the browser built the request; this only forwards it with the app token.
      if (req.method === "POST" && sub === "/voucher/sign") {
        const body = await readJson(req);
        return raw(res, await signVoucher(body.voucherRequest));
      }
      // Decrypt voucher: gated on the uid THIS server resolved, plus the role.
      if (req.method === "POST" && sub === "/voucher/decrypt") {
        const body = await readJson(req);
        try { return raw(res, await decryptVoucher(uid, role, body.voucherRequest)); }
        catch (e) { return json(res, 403, { error: String(e.message || e) }); }
      }
      return next();
    } catch (e) {
      return json(res, 502, { error: String(e.message || e) });
    }
  };
}
