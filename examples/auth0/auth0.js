import * as jose from "jose";

const DOMAIN = process.env.AUTH0_DOMAIN;              // your-tenant.eu.auth0.com
const CLIENT_ID = process.env.AUTH0_CLIENT_ID;
const CLIENT_SECRET = process.env.AUTH0_CLIENT_SECRET;

export function missingConfig() {
  return Object.entries({ AUTH0_DOMAIN: DOMAIN, AUTH0_CLIENT_ID: CLIENT_ID,
    AUTH0_CLIENT_SECRET: CLIENT_SECRET })
    .filter(([, v]) => !v).map(([k]) => k);
}

const issuer = () => `https://${DOMAIN}/`;
const jwks = jose.createRemoteJWKSet(new URL(`https://${DOMAIN}/.well-known/jwks.json`));

export function authorizeUrl(redirectUri, state) {
  const u = new URL(`https://${DOMAIN}/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", CLIENT_ID);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", "openid profile email");
  u.searchParams.set("state", state);
  return u.toString();
}

/** Swap the code for tokens, then verify the id token rather than trusting it. */
export async function exchangeCode(code, redirectUri) {
  const res = await fetch(`https://${DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
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
 * Record the Tide identity on the Auth0 user.
 *
 * `app_metadata` rather than `user_metadata`, because the user must not be able to edit it. Note
 * what goes in: the vuid and nothing else. Roles stay out, because an Auth0 Action could copy them
 * into a token and then your tenant would be minting authorisation again.
 */
export async function storeVuid(userId, vuid) {
  const token = await managementToken();
  const res = await fetch(`https://${DOMAIN}/api/v2/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({ app_metadata: { tide_vuid: vuid } }),
  });
  if (!res.ok) throw new Error("could not store the vuid: " + (await res.text()));
}

async function managementToken() {
  const res = await fetch(`https://${DOMAIN}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      audience: `https://${DOMAIN}/api/v2/`,
    }),
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error("no management token, authorise this app for the Management API: "
      + (body.error_description ?? body.error));
  }
  return body.access_token;
}
