# minidauth with AWS Cognito

Cognito owns the login. minidauth supplies an identity the Tide network vouches for and roles a
quorum decides. The Cognito token never carries a role, and that is the point.

## The rule this example exists to demonstrate

Cognito can put anything you like in a token, including a Pre Token Generation trigger that adds
group claims. Do not put authorisation there. **A role that arrives in a token your AWS account can
mint is a role your AWS account can grant itself**, which is exactly the single point of failure
this is meant to remove.

So the token carries identity, `custom:tide_vuid` carries the link, and `/protected` in
[server.js](server.js) reads roles from minidauth on every request. Nothing you can change in the
AWS console will get you into that page.

## What to create in Cognito

1. **A user pool.** Defaults are fine. Note the pool id, like `eu-west-2_ABC123`.
2. **A custom attribute** on the pool named `tide_vuid`, string, mutable. It appears in tokens and
   in the API as `custom:tide_vuid`.
3. **An app client**, with a secret or without, either works. Enable the authorization code grant
   and the `openid` and `email` scopes. Set the callback URL to `http://localhost:3001/callback`.
4. **A Cognito domain** for the hosted UI, which gives you
   `https://<something>.auth.<region>.amazoncognito.com`.
5. **Credentials for the app** with `cognito-idp:AdminUpdateUserAttributes` on that pool, so the
   example can write the vuid back. The standard AWS environment variables are picked up.

Then register this app's callback with minidauth, because the enclave will not return to a URI it
has no signature for:

```sh
curl -sX POST localhost:8081/tide/enclave/settings -H "Authorization: Bearer $OPS" \
  -H 'Content-Type: application/json' -d '{
    "regOn": true, "backupOn": false,
    "logoUrl": "https://yourapp.example/logo.png",
    "imageUrl": "https://yourapp.example/bg.png",
    "redirectUris": ["http://localhost:8081/console", "http://localhost:3001/tide/callback"],
    "clientOrigins": ["http://localhost:8081", "http://localhost:3001"]
  }'
```

And add an operator for the app in minidauth's `operators.json`:

```json
{ "name": "your-app", "token": "change-me-app", "roles": ["relying-party"] }
```

`relying-party` grants nothing on its own. The app can start a Tide sign-in, finish one and read
grants. It cannot approve a change or touch the vendor key.

## Run it

```sh
npm install
export COGNITO_REGION=eu-west-2
export COGNITO_USER_POOL_ID=eu-west-2_ABC123
export COGNITO_CLIENT_ID=...
export COGNITO_CLIENT_SECRET=...          # only if the app client has one
export COGNITO_DOMAIN=https://your-domain.auth.eu-west-2.amazoncognito.com
export MINIDAUTH_TOKEN=change-me-app
npm start                                  # http://localhost:3001
```

Open it, sign in through the hosted UI, link a Tide identity, then try the protected page. It
refuses until somebody holds `vault-reader`, which is granted through the quorum in minidauth's
console.

The page tells you which variables are missing rather than failing at the first request, so it is
worth starting it before you have finished the AWS side.

| | |
|---|---|
| `MINIDAUTH_URL` | `http://localhost:8081` |
| `MINIDAUTH_TOKEN` | the `relying-party` token |
| `APP_URL` | `http://localhost:3001` |

## Status

The minidauth half of this is the same code as
[the Better Auth example](../better-auth), which is exercised against the live network. The Cognito
half is written from the API and has not been run against a real user pool yet. If you run it and it
is wrong, that is worth an issue.
