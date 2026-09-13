# minidauth with Better Auth

A working example of the claim in the main README: keep the login you already have, and add an
identity the network vouches for and roles a quorum decides.

Better Auth owns accounts, sessions and passwords, exactly as it would on its own. minidauth is
consulted for two things it is better at, and nothing else.

## What it shows

**One extra field.** `tideVuid` on the user table, in [auth.js](auth.js). Everything else about
authentication is untouched.

**Authorisation that this app cannot grant itself.** [server.js](server.js) `/protected` reads roles
from minidauth on every request, not from its own database. Editing `app.db` will not let anybody
in, because the roles come from a grant record only a quorum can change.

**A callback that cannot be forged into a link.** The vuid is proven by minidauth, which verifies
the blind signature before it answers. What the app still has to get right is that a reply belongs
to a sign-in it started, for the account that started it.

**A credential worth leaking.** The app's token holds `relying-party`, which grants nothing on its
own. It can start a sign-in, finish one, and read grants. It cannot approve a change or touch the
vendor key.

## Run it

minidauth needs to be running first, with a vendor key created and its policies deployed. Then
register this app's callback, because the enclave will not return to a URI it has no signature for:

```sh
curl -sX POST localhost:8081/tide/enclave/settings -H "Authorization: Bearer $OPS" \
  -H 'Content-Type: application/json' -d '{
    "regOn": true, "backupOn": false,
    "logoUrl": "https://yourapp.example/logo.png",
    "imageUrl": "https://yourapp.example/bg.png",
    "redirectUris": ["http://localhost:8081/console", "http://localhost:3000/tide/callback"],
    "clientOrigins": ["http://localhost:8081", "http://localhost:3000"]
  }'
```

Add an operator for the app, in `operators.json` next to minidauth:

```json
{ "name": "sample-app", "token": "dev-sample-app-token", "roles": ["relying-party"] }
```

Then:

```sh
npm install
npx @better-auth/cli migrate --yes
npm start                                  # http://localhost:3000
```

Create an account, link a Tide identity, and open the protected page. It will refuse you until
somebody holds `vault-reader`, which is granted through the quorum in minidauth's console at
http://localhost:8081/console.

| | |
|---|---|
| `MINIDAUTH_URL` | `http://localhost:8081` |
| `MINIDAUTH_TOKEN` | `dev-sample-app-token` |
| `APP_URL` | `http://localhost:3000` |
| `APP_SECRET` | set a real one, Better Auth wants 32 characters or more |

## What it does not show

Encryption. That happens in the browser inside the Tide enclave, not in this app, so a fair example
of it is a page of enclave plumbing rather than an integration. minidauth's own `/console/vault`
does exactly that, and is the shorter way to see it work.


## Tideless: encrypt & decrypt with no Tide account

This example also mounts a **tideless** page at `/tideless` (see
[`../shared/tideless.js`](../shared/tideless.js)). It is the opposite of linking a Tide identity: the
signed-in Better Auth user encrypts and decrypts with **no Tide account and no doken**. Their own
the Better Auth account id is the subject, and a role a quorum granted that id is the gate; minidauth issues the
vouchers and the ORK cohort does the crypto. The browser holds no credential — the server proxies
the vouchers and sets the uid from its own verified session, so a page cannot read as another user.

Two prerequisites, both one-time:

- minidauth must have a **PUBLIC** decrypt policy (voucher-gated, not doken-gated). A key's decrypt
  policy is either PUBLIC or PRIVATE, so this is a different key/policy from the account-linked flow
  above. See [docs/running.md](../../docs/running.md).
- Grant the user's id a role as a tideless subject, through the quorum:

  ```sh
  curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
    -H 'Content-Type: application/json' -d '{"vuid":"<better auth user id>","role":"vault-reader","tideless":true}'
  # $BOB and $CAROL authorize, then commit
  ```

Then sign in and open `/tideless`. The trade this makes — minidauth becomes the authority for these
users' reads — is spelled out in [examples/tideless](../tideless#the-trade-you-are-making).
