/**
 * Checking the network's signature on a payout, here, with nothing but Node.
 *
 * This is what makes a signed payout worth more than a row that says "signed". The signature is
 * plain Ed25519 under the vendor key, a key no machine holds, so anyone with the public half can
 * check it: this app, an auditor, the bank. Nobody without a quorum can produce one.
 */
import crypto from "node:crypto";

const MINIDAUTH_URL = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const MINIDAUTH_TOKEN = process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token";

/* The instruction is rebuilt from the row every time rather than read from it. The payout's own id is
 * in there, so a signature cannot be lifted onto a different payout for the same amount, and the
 * amount comes first because that is where the payment policy's contract looks for it. */
export const instructionFor = (p) => `amount=${p.amount};to=${p.payee_id};ref=${p.id}`;

/* The cohort signs the request's draft as it was sent, and the draft is a TideMemory: a version,
 * a length, then the bytes. Both little-endian int32. */
function draftOf(text) {
  const body = Buffer.from(text, "utf8");
  const head = Buffer.alloc(8);
  head.writeInt32LE(1, 0);
  head.writeInt32LE(body.length, 4);
  return Buffer.concat([head, body]);
}

let vendorKey = null;

/* minidauth hands out the vendor public key as 32 bytes of hex. Node wants it wrapped as SPKI, which
 * for Ed25519 is a fixed 12-byte prefix. */
async function vendorPublicKey() {
  if (vendorKey) return vendorKey;
  const res = await fetch(MINIDAUTH_URL + "/tide/enclave/config", {
    headers: { Authorization: "Bearer " + MINIDAUTH_TOKEN },
  });
  if (!res.ok) throw new Error("could not read the vendor key from minidauth");
  const hex = (await res.json()).gVVK;
  if (!/^[0-9a-f]{64}$/i.test(hex ?? "")) throw new Error("minidauth gave no vendor key");
  vendorKey = crypto.createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(hex, "hex")]),
    format: "der",
    type: "spki",
  });
  return vendorKey;
}

export async function verifyInstruction(instruction, signatureB64) {
  if (!signatureB64) return { valid: false, reason: "no signature" };
  const sig = Buffer.from(signatureB64, "base64");
  if (sig.length !== 64) return { valid: false, reason: "not an Ed25519 signature" };
  try {
    const ok = crypto.verify(null, draftOf(instruction), await vendorPublicKey(), sig);
    return ok ? { valid: true }
      : { valid: false, reason: "the network did not sign this instruction" };
  } catch (e) {
    return { valid: false, reason: e.message };
  }
}
