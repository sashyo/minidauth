/**
 * Delete what setup.js created, so an example does not quietly become a bill.
 *
 * Only touches the pool named in .env, and refuses if that file is missing, because guessing which
 * user pool somebody meant is not a mistake worth making.
 */
import {
  CognitoIdentityProviderClient,
  DeleteUserPoolCommand,
  DeleteUserPoolDomainCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import fs from "node:fs";

if (!fs.existsSync(".env")) {
  console.error("No .env here, so there is nothing this script is sure it created.");
  process.exit(1);
}
const env = Object.fromEntries(fs.readFileSync(".env", "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trim().startsWith("#"))
  .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));

const { COGNITO_REGION: region, COGNITO_USER_POOL_ID: poolId, COGNITO_DOMAIN: domain } = env;
if (!region || !poolId) {
  console.error(".env names no pool, so there is nothing to delete.");
  process.exit(1);
}

const cognito = new CognitoIdentityProviderClient({ region });

if (domain) {
  const prefix = new URL(domain).hostname.split(".")[0];
  await cognito.send(new DeleteUserPoolDomainCommand({ Domain: prefix, UserPoolId: poolId }))
    .then(() => console.log("  deleted domain", prefix))
    .catch((e) => console.log("  domain not deleted:", e.message));
}

await cognito.send(new DeleteUserPoolCommand({ UserPoolId: poolId }));
console.log("  deleted user pool", poolId);

fs.rmSync(".env");
console.log("  removed .env");
