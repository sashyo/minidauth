/**
 * Make a key pair for an application.
 *
 * The private key stays with the app. The public one goes in minidauth's operators.json, where it
 * cannot be presented as a credential by anyone who reads the file.
 *
 *   node ../shared/keygen.js your-app
 */
import crypto from "node:crypto";

const name = process.argv[2] ?? "your-app";
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

const pub = publicKey.export({ type: "spki", format: "der" }).toString("base64");
const priv = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");

console.log("Put this in minidauth's operators.json:\n");
console.log(JSON.stringify({ name, publicKey: pub, roles: ["relying-party"] }, null, 2));
console.log("\nAnd give the app these, keeping the key out of the repo:\n");
console.log(`MINIDAUTH_CLIENT_NAME=${name}`);
console.log(`MINIDAUTH_CLIENT_KEY=${priv}`);
