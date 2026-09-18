// One-time key generation for the sealing setup. Writes, into the shared /keys volume, the Ed25519
// key pair every integration uses:
//   usertoken.key   the PRIVATE key (PKCS8 PEM). Each app mounts this and signs its short-lived
//                   reader tokens with it. Keep it out of your repo.
//   authpub.b64     the PUBLIC key (SPKI DER, base64). The sidecar reads this to verify those
//                   tokens. Safe to share; it is not a credential.
// Idempotent: if the private key already exists, it does nothing, so restarts never rotate the key.
import crypto from "node:crypto";
import { existsSync, writeFileSync, readFileSync } from "node:fs";

const DIR = process.env.KEYS_DIR ?? "/keys";
const KEY = `${DIR}/usertoken.key`;
const PUB = `${DIR}/authpub.b64`;

if (existsSync(KEY)) {
  console.log(`keygen: ${KEY} already exists, keeping it`);
} else {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  writeFileSync(KEY, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileSync(PUB, publicKey.export({ type: "spki", format: "der" }).toString("base64"));
  console.log(`keygen: wrote ${KEY} (private, app-signing) and ${PUB} (public, sidecar-verifying)`);
}

// Always (re)emit the operators.json snippet, so a user can register this app key with minidauth.
const pub = readFileSync(PUB, "utf8").trim();
console.log("\nRegister this app key in minidauth's operators.json:\n");
console.log(JSON.stringify({ name: "sample-app", publicKey: pub, roles: ["relying-party"] }, null, 2));
