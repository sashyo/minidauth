/**
 * Create everything Cognito needs for this example, and write the config out.
 *
 * The manual version of this is a user pool, a custom attribute, an app client with the right
 * flows, a hosted UI domain, and then telling minidauth about the callback. That is five consoles
 * and a lot of places to make a small mistake, so it is done here instead.
 *
 * Safe to run twice: it reuses anything already named in .env rather than making a second copy.
 */
import {
  CognitoIdentityProviderClient,
  CreateUserPoolCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolDomainCommand,
  DescribeUserPoolCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import crypto from "node:crypto";
import fs from "node:fs";

const REGION = process.env.AWS_REGION ?? process.env.COGNITO_REGION;
const APP_URL = process.env.APP_URL ?? "http://localhost:3001";
const MINIDAUTH_URL = process.env.MINIDAUTH_URL ?? "http://localhost:8081";
const OPS = process.env.MINIDAUTH_OPS_TOKEN;
const POOL_NAME = process.env.COGNITO_POOL_NAME ?? "minidauth-example";

if (!REGION) {
  console.error("Set AWS_REGION, and make sure your AWS credentials are in the environment.");
  process.exit(1);
}

const env = fs.existsSync(".env")
  ? Object.fromEntries(fs.readFileSync(".env", "utf8").split("\n")
      .filter((l) => l.includes("=") && !l.trim().startsWith("#"))
      .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]))
  : {};

const cognito = new CognitoIdentityProviderClient({ region: REGION });
const say = (...a) => console.log(" ", ...a);

async function userPool() {
  if (env.COGNITO_USER_POOL_ID) {
    // Prove it still exists before trusting the file.
    await cognito.send(new DescribeUserPoolCommand({ UserPoolId: env.COGNITO_USER_POOL_ID }));
    say("reusing user pool", env.COGNITO_USER_POOL_ID);
    return env.COGNITO_USER_POOL_ID;
  }

  const res = await cognito.send(new CreateUserPoolCommand({
    PoolName: POOL_NAME,
    UsernameAttributes: ["email"],
    AutoVerifiedAttributes: ["email"],
    // Defined at creation because a custom attribute cannot be removed later, only added.
    Schema: [{
      Name: "tide_vuid",
      AttributeDataType: "String",
      Mutable: true,
      Required: false,
      StringAttributeConstraints: { MinLength: "0", MaxLength: "128" },
    }],
    Policies: { PasswordPolicy: { MinimumLength: 8, RequireUppercase: false,
      RequireLowercase: false, RequireNumbers: false, RequireSymbols: false } },
  }));
  const id = res.UserPool.Id;
  say("created user pool", id);
  return id;
}

async function appClient(poolId) {
  if (env.COGNITO_CLIENT_ID) {
    say("reusing app client", env.COGNITO_CLIENT_ID);
    return { id: env.COGNITO_CLIENT_ID, secret: env.COGNITO_CLIENT_SECRET ?? "" };
  }

  const res = await cognito.send(new CreateUserPoolClientCommand({
    UserPoolId: poolId,
    ClientName: "minidauth-example",
    GenerateSecret: true,
    AllowedOAuthFlows: ["code"],
    AllowedOAuthScopes: ["openid", "email"],
    AllowedOAuthFlowsUserPoolClient: true,
    SupportedIdentityProviders: ["COGNITO"],
    CallbackURLs: [`${APP_URL}/callback`],
    LogoutURLs: [APP_URL],
    // The example writes the vuid back with admin credentials, not with the user's token.
    ExplicitAuthFlows: ["ALLOW_REFRESH_TOKEN_AUTH"],
  }));
  say("created app client", res.UserPoolClient.ClientId);
  return { id: res.UserPoolClient.ClientId, secret: res.UserPoolClient.ClientSecret ?? "" };
}

async function hostedDomain(poolId) {
  if (env.COGNITO_DOMAIN) {
    say("reusing hosted domain", env.COGNITO_DOMAIN);
    return env.COGNITO_DOMAIN;
  }
  // Has to be unique across the whole region, so it gets a random suffix rather than a nice name.
  const prefix = `minidauth-${crypto.randomBytes(4).toString("hex")}`;
  await cognito.send(new CreateUserPoolDomainCommand({ Domain: prefix, UserPoolId: poolId }));
  const url = `https://${prefix}.auth.${REGION}.amazoncognito.com`;
  say("created hosted domain", url);
  return url;
}

/** Tell minidauth about this app's callback, merging rather than replacing what is already signed. */
async function registerWithMinidauth() {
  if (!OPS) {
    say("skipped minidauth registration, set MINIDAUTH_OPS_TOKEN to do it automatically");
    return false;
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
  if (!res.ok) throw new Error("minidauth refused the settings: " + (await res.text()));
  say("registered", `${APP_URL}/tide/callback`, "with minidauth");
  return true;
}

console.log("Setting up Cognito in", REGION);
const poolId = await userPool();
const client = await appClient(poolId);
const domain = await hostedDomain(poolId);
const registered = await registerWithMinidauth().catch((e) => {
  say("could not register with minidauth:", e.message);
  return false;
});

fs.writeFileSync(".env", `# Written by npm run setup. Safe to edit.
COGNITO_REGION=${REGION}
COGNITO_USER_POOL_ID=${poolId}
COGNITO_CLIENT_ID=${client.id}
COGNITO_CLIENT_SECRET=${client.secret}
COGNITO_DOMAIN=${domain}
APP_URL=${APP_URL}
MINIDAUTH_URL=${MINIDAUTH_URL}
MINIDAUTH_TOKEN=${process.env.MINIDAUTH_TOKEN ?? "dev-sample-app-token"}
`);
say("wrote .env");

console.log("\nReady. Start it with:\n\n  npm start\n");
if (!registered) {
  console.log("First register the callback with minidauth, or the enclave will refuse to return:\n");
  console.log(`  MINIDAUTH_OPS_TOKEN=<ops token> npm run setup\n`);
}
