# minidauth with AWS Cognito

Cognito owns the login. minidauth supplies an identity the Tide network vouches for and roles a
quorum decides. The Cognito token never carries a role, and that is the point.

## Run it

You need AWS credentials in the environment and minidauth already running with its policies
deployed.

```sh
npm install
AWS_REGION=ap-southeast-2 MINIDAUTH_OPS_TOKEN=<your ops token> npm run setup
npm start                                   # http://localhost:3001
```

`setup` creates the user pool, the `tide_vuid` custom attribute, an app client with the right OAuth
flows and callback, and a hosted UI domain. It then registers this app's callback with minidauth,
merging with whatever is already signed rather than replacing it, and writes everything to `.env`.
Run it again any time: it reuses what `.env` already names instead of making a second copy.

Then open the page, sign in through the hosted UI, link a Tide identity, and try the protected page.
It refuses until somebody holds `vault-reader`, which is granted through the quorum in minidauth's
console at http://localhost:8081/console.

When you are finished:

```sh
npm run teardown            # deletes the pool and domain it created, and the .env
```

One thing still needs doing by hand, because it is minidauth's file rather than AWS's. Add an
operator for the app in minidauth's `operators.json`:

```json
{ "name": "your-app", "token": "dev-sample-app-token", "roles": ["relying-party"] }
```

`relying-party` grants nothing on its own. The app can start a Tide sign-in, finish one and read
grants. It cannot approve a change or touch the vendor key, so leaking that token hands nobody a
role.

## The rule this example exists to demonstrate

Cognito can put anything you like in a token, including a Pre Token Generation trigger that adds
group claims. Do not put authorisation there. **A role that arrives in a token your AWS account can
mint is a role your AWS account can grant itself**, which is exactly the single point of failure
this is meant to remove.

So the token carries identity, `custom:tide_vuid` carries the link, and `/protected` in
[server.js](server.js) reads roles from minidauth on every request. Nothing you can change in the
AWS console will get you into that page.

## What setup created, if you would rather do it yourself

| | |
|---|---|
| user pool | email sign-in, with a `tide_vuid` string attribute, mutable |
| app client | authorization code grant, `openid` and `email`, callback `/callback` |
| hosted domain | `https://minidauth-xxxx.auth.<region>.amazoncognito.com` |
| minidauth | `/tide/callback` added to the signed redirect URIs, and the origin to the signed origins |

The app also needs `cognito-idp:AdminUpdateUserAttributes` on the pool, to write the vuid back after
a link. The standard AWS environment variables are picked up.

## Status

The minidauth half of this is the same code as [the Better Auth example](../better-auth), which is
exercised against the live network. The Cognito half is written from the API and has not been run
against a real user pool yet. If you run it and it is wrong, that is worth an issue.


## Tideless: encrypt & decrypt with no Tide account

This example also mounts a **tideless** page at `/tideless` (see
[`../shared/tideless.js`](../shared/tideless.js)). It is the opposite of linking a Tide identity: the
signed-in Cognito user encrypts and decrypts with **no Tide account and no doken**. Their own
the Cognito subject (sub) is the subject, and a role a quorum granted that id is the gate; minidauth issues the
vouchers and the ORK cohort does the crypto. The browser holds no credential — the server proxies
the vouchers and sets the uid from its own verified session, so a page cannot read as another user.

Two prerequisites, both one-time:

- minidauth must have a **PUBLIC** decrypt policy (voucher-gated, not doken-gated). A key's decrypt
  policy is either PUBLIC or PRIVATE, so this is a different key/policy from the account-linked flow
  above. See [docs/running.md](../../docs/running.md).
- Grant the user's id a role as a tideless subject, through the quorum:

  ```sh
  curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
    -H 'Content-Type: application/json' -d '{"vuid":"<cognito user id>","role":"vault-reader","tideless":true}'
  # $BOB and $CAROL authorize, then commit
  ```

Then sign in and open `/tideless`. The trade this makes — minidauth becomes the authority for these
users' reads — is spelled out in [examples/tideless](../tideless#the-trade-you-are-making).
