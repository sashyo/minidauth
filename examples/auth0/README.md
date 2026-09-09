# minidauth with Auth0

Auth0 owns the login. minidauth supplies an identity the Tide network vouches for and roles a quorum
decides. The Auth0 token never carries a role, and that is the point.

## Run it

In Auth0, create a **Regular Web Application** and set its allowed callback URL to
`http://localhost:3002/callback`. Then authorise that same application for the **Management API**
with the `update:users` scope, so it can write the link back.

Register this app's Tide callback with minidauth, which merges rather than replaces:

```sh
MINIDAUTH_OPS_TOKEN=<ops token> APP_URL=http://localhost:3002 \
  node ../shared/register-callback.js
```

Then:

```sh
npm install
export AUTH0_DOMAIN=your-tenant.au.auth0.com
export AUTH0_CLIENT_ID=...
export AUTH0_CLIENT_SECRET=...
export MINIDAUTH_TOKEN=dev-sample-app-token
npm start                                   # http://localhost:3002
```

## Where the link is stored, and why

`app_metadata.tide_vuid`, not `user_metadata`, because the user must not be able to edit it.

Roles stay out of Auth0 entirely. An Action can copy `app_metadata` into a token, and a role that
arrives in a token your tenant can mint is a role your tenant can grant itself, which is the single
point of failure this is meant to remove. `/protected` reads roles from minidauth on every request
instead.

## Status

Written from the Auth0 API and not yet run against a real tenant. The minidauth half is shared with
[the Better Auth example](../better-auth), which is exercised against the live network.
