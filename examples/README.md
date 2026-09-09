# Examples

Four auth systems, one integration. The point of having several is that the minidauth part does not
change: [`shared/minidauth.js`](shared/minidauth.js) is the same file in all of them.

**Start here: [notes](notes)**, which is the only one that shows what minidauth is for rather than
how to wire it in. You write a note, it is encrypted in the enclave, and the page shows you the
database containing nothing but ciphertext.

The rest are integrations. Same three steps in each, with a different login provider:

| | | |
|---|---|---|
| [better-auth](better-auth) | :3000 | Runs locally, exercised against the live network |
| [supabase](supabase) | :3004 | **Run end to end**, with a [walkthrough](supabase#what-it-looks-like) |
| [clerk](clerk) | :3003 | **Run end to end**, with a [walkthrough](clerk#what-it-looks-like) |
| [auth0](auth0) | :3002 | **Run end to end**, with a [walkthrough](auth0#what-it-looks-like) |
| [cognito](cognito) | :3001 | `npm run setup` builds the pool, but AWS wants a card |

## The pattern, in three steps

**1. Store one field.** The Tide identity, on your user record. Where it goes depends on what you
already run, and the only rule is that the user must not be able to edit it:

| | |
|---|---|
| Better Auth | a `tideVuid` column, `input: false` |
| Supabase | `raw_app_meta_data.tide_vuid`, service role only |
| Clerk | `privateMetadata.tideVuid` |
| Auth0 | `app_metadata.tide_vuid` |
| Cognito | `custom:tide_vuid` |

**2. Add one callback route.** Send the browser to `loginUrl(...)`, and when the enclave returns,
`completeLogin(...)` gives you a vuid minidauth has already verified. Your app still has to check
the reply belongs to a sign-in it started, for the account that started it. Every example does that
with a short-lived map and refuses anything else with a 400.

**3. Read authorisation, do not store it.** `rolesFor(vuid)` on every request. This is the step that
matters: it is what makes a role something your database cannot decide.

## Why the app needs a minidauth token

It is a fair thing to ask, because it is not what makes the roles trustworthy. Those come from a
grant record the network attested, and the token adds nothing to that.

What it does buy is two things.

**Cost.** Starting a sign-in registers a voucher session, and issuing a voucher spends the vendor key
and draws on the licence's account quota. An open endpoint is an open tap.

**Not publishing your governance.** `/iga/grants/{vuid}` is the answer to who may read what. There is
no reason for that to be readable by anyone who can reach the port.

What it is not: proof that the answer came from minidauth. The token authenticates your app *to*
minidauth, not the other way round, so on anything but localhost the connection between them wants
TLS like any other trusted call.

Leaking it grants nobody a role. `relying-party` carries no privileges: no route requires it, so it
cannot approve a change, deploy a policy or touch the key. The worst it costs you is quota and a
look at the grant record.

### Better: do not share a secret at all

A shared secret has to exist at both ends, so minidauth's operators file is a copy of every app's
credential. Give it a public key instead:

```sh
node ../shared/keygen.js your-app     # public key for operators.json, private key for the app
export MINIDAUTH_CLIENT_NAME=your-app
export MINIDAUTH_CLIENT_KEY=<the private key it printed>
```

The shared client picks that up on its own and signs a fresh assertion per call instead of sending
`MINIDAUTH_TOKEN`. Each one names this service, lives for a minute, and is accepted once, so an
assertion observed in transit is worth nothing. A copy of minidauth's operators file is worth nothing
either, because a public key cannot be presented as a credential.

## The mistake all four are written to avoid

Every one of these systems will happily put custom claims in a token. Auth0 has Actions, Clerk has
session token metadata, Supabase puts `app_metadata` straight into the JWT, Better Auth has
additional fields, Cognito has Pre Token Generation triggers.

Do not put roles there. **A role that arrives in a token your own system can mint is a role your own
system can grant itself**, and you are back to a single point of failure. The token carries identity;
the grant record carries authorisation, and only a quorum can change it.

## Encryption

None of these show it, because it happens in the browser inside the Tide enclave rather than in your
server. minidauth's own `/console/vault` does exactly that and is the shorter way to see it work.
