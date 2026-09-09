import * as jose from "jose";
import {
  CognitoIdentityProviderClient,
  AdminUpdateUserAttributesCommand,
} from "@aws-sdk/client-cognito-identity-provider";

const REGION = process.env.COGNITO_REGION;
const POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;
const DOMAIN = process.env.COGNITO_DOMAIN;

export const config = { REGION, POOL_ID, CLIENT_ID, DOMAIN };

export function missingConfig() {
  return Object.entries({ COGNITO_REGION: REGION, COGNITO_USER_POOL_ID: POOL_ID,
    COGNITO_CLIENT_ID: CLIENT_ID, COGNITO_DOMAIN: DOMAIN })
    .filter(([, v]) => !v).map(([k]) => k);
}

const issuer = () => `https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}`;
const jwks = jose.createRemoteJWKSet(new URL(issuer() + "/.well-known/jwks.json"));

/** Where to send the browser to sign in. Cognito's Hosted UI, unchanged. */
export function authorizeUrl(redirectUri, state) {
  const u = new URL(DOMAIN.replace(/\/+$/, "") + "/oauth2/authorize");
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", CLIENT_ID);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", "openid email");
  u.searchParams.set("state", state);
  return u.toString();
}

/** Swap the code for tokens, then verify the id token rather than trusting it. */
export async function exchangeCode(code, redirectUri) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: redirectUri,
  });
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (CLIENT_SECRET) {
    headers.Authorization =
      "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  }

  const res = await fetch(DOMAIN.replace(/\/+$/, "") + "/oauth2/token", {
    method: "POST", headers, body,
  });
  const tokens = await res.json();
  if (!res.ok) throw new Error(tokens.error_description ?? tokens.error ?? "token exchange failed");

  const { payload } = await jose.jwtVerify(tokens.id_token, jwks, {
    issuer: issuer(),
    audience: CLIENT_ID,
  });
  return payload;
}

/**
 * Record the Tide identity against the Cognito user.
 *
 * A custom attribute, so the mapping lives with the account rather than in a table beside it. Note
 * what is stored: the vuid and nothing else. Roles are deliberately not copied here, because an
 * attribute this app can write is an attribute this app can forge.
 */
export async function storeVuid(username, vuid) {
  const client = new CognitoIdentityProviderClient({ region: REGION });
  await client.send(new AdminUpdateUserAttributesCommand({
    UserPoolId: POOL_ID,
    Username: username,
    UserAttributes: [{ Name: "custom:tide_vuid", Value: vuid }],
  }));
}
