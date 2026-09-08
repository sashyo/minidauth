# minidauth

Mini decentralised auth. A small service that gives an existing auth system a key nobody holds.

Your login stays where it is: Cognito, Better Auth, Keycloak, Auth.js, a hand-rolled form. minidauth
sits beside it and adds the parts that are hard to build and dangerous to get wrong: a vendor key
that exists only as shares across the Tide network, encryption keyed to that, and a governance
quorum that decides who may decrypt.

## What problem this actually solves

Most systems can already tell you *who* someone is. What they cannot do is stop themselves reading
the data. The database holds the rows, the app holds the key, and anyone who takes the machine takes
both.

minidauth moves the key out. It is never assembled anywhere: the ORK network holds shares, no single
node can reconstruct it, and decryption is authorised by a policy the network enforces rather than
by a flag in your database. Compromising your application gets an attacker ciphertext and no way to
read it.

The claim is deliberately narrow:

> **A stolen copy of your database contains nothing readable, and no key material to make it
> readable.** Not a backup, not a dump, not a compromised app server.

It is not a claim that nobody can read the data. minidauth holds the vendor root key, so whoever runs
minidauth can ultimately authorise reads, and a quorum of your own operators can grant themselves the
role that reads. Those are deliberate: access has to be recoverable and reviewable. What the design
removes is any *single* party, especially your application, being able to do it alone.

## What it is not

- **Not an identity provider.** No user store, no password reset, no enrolment. Your auth system owns
  users; minidauth owns keys, policies and roles.
- **Not a database.** State is two JSON files. It is small on purpose.
- **Not a place to put your app.** Run it separately. The application is the thing you assume gets
  compromised; the key must not be there.

## How it fits

```
                        ┌──────────────────────┐
                        │    user's browser    │
                        └───┬──────────────┬───┘
             normal login   │              │   Tide sign-in, and any
                            │              │   browser-side crypto, run
                            ▼              ▼   in the enclave
  ┌──────────────────────────────┐   ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
  │      your app + auth         │                          ╎
  │  Cognito · Better Auth ·     │   five HTTP calls        ╎
  │  Keycloak · Auth.js          │ ───────────────────────▶ ╎  ┌────────────────────────┐
  │                              │                          ╎  │       minidauth        │
  │  owns users, sessions, UI    │ ◀─────────────────────── ╎  │  vendor key · policies │
  │  stores one column: vuid     │   vuid, doken, roles     ╎  │  governance · console  │
  └──────────────────────────────┘                          ╎  └───────────┬────────────┘
                                                            ╎              │
     never talks to the ORK network ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌              ▼
                                                                  Tide ORK network
                                                            key shares · enforces policy
```

Two things reach the ORK network: **minidauth**, and the **user's browser** during sign-in. Your
application never does. It talks only to minidauth, over ordinary HTTP, and needs to know nothing
about threshold cryptography.

Your app also never holds anything that can grant a role. That is the point, and it is why the
governance console is served by minidauth rather than embedded in your admin panel.

## The integration surface

Five calls. None of them requires you to understand threshold cryptography.

| | |
|---|---|
| `POST /tide/enclave/login-url` | where to send the user to prove a Tide identity |
| `POST /tide/enclave/callback` | turn the returned proof into `{ vuid, doken, roles }` |
| `GET /iga/grants/{vuid}` | what roles that identity holds |
| `GET /vault/encrypt-policy` | the public credential a browser needs to encrypt |
| `POST /vault/decrypt` | decrypt, for a doken holding the right role |

### One constraint to design around

Dokens are **EdDSA**. Node's `jsonwebtoken` has no Ed25519 support and neither does stock .NET, so a
verifier on those stacks cannot check a doken locally and must ask minidauth. Check this before
promising an integration; it is the most common thing that turns a day's work into a week's.

## Using it with your auth system

The pattern is the same everywhere. Your system authenticates the user as it always did. Separately,
the user proves a Tide identity, and you store the resulting `vuid` against your own user record. From
then on, `vuid` is what authorisation is keyed to.

Adding Tide as a second factor rather than replacing your login is deliberate: nobody has to migrate
their user table to try this.

### AWS Cognito

Cognito keeps the user pool, the hosted UI and the tokens. minidauth keeps the key.

1. Add a custom attribute `custom:tide_vuid` to your user pool.
2. After Cognito sign-in, send the user through `POST /tide/enclave/login-url` and handle the
   callback in a Lambda or your backend. Write the returned `vuid` to `custom:tide_vuid`.
3. For authorisation, do **not** read roles from the Cognito token. Read them from the doken, or from
   `GET /iga/grants/{vuid}`. A Cognito group is something your admins can change; a Tide role takes a
   quorum, and that difference is the entire security argument.
4. Encrypt in the browser with the public encrypt policy. Decrypt through minidauth with the doken.

A Pre Token Generation trigger can copy the vuid into the Cognito token for convenience. Copy the
`vuid` only, never the roles. A role that arrived via a Cognito trigger is a role your AWS account
can mint, which puts you back where you started.

### Better Auth

Closest fit, since you control the schema.

1. Add `tideVuid` to the user table.
2. A plugin endpoint starts the enclave sign-in and completes the callback.
3. Keep the doken in the session, never in the database.
4. Gate decryption on `GET /iga/grants/{vuid}`.

### Keycloak / Auth.js / anything else

Same three steps: somewhere to store `vuid`, a route that completes the enclave callback, and
authorisation read from grants rather than from your own tables. If your stack cannot verify EdDSA,
verify through minidauth instead.

### WordPress and other apps you do not control

Where you cannot add a column, key the mapping on whatever stable id the app has. The rest is
unchanged.

## Encrypt and decrypt

Two shapes, and which you want depends on whether the writer has an identity.

**Open write, governed read.** An encrypt-only policy is `PUBLIC` and `IMPLICIT`, so anyone can
encrypt with no identity at all, a stranger filling in a contact form for instance. Decryption runs
under a `PRIVATE` policy that requires a doken carrying a granted role. Publishing the encrypt policy
is safe because the ORK refuses to let it authorise anything but encryption; `GET /vault/encrypt-policy`
will only ever serve a policy whose models are exactly `[PolicyEnabledEncryption:1]`, and refuses
otherwise.

**Identity at both ends.** `/vault/encrypt` and `/vault/decrypt` do the work through the ORK network
with a doken required either way. Simpler to call, but no anonymous writes, and the plaintext passes
through minidauth.

Browser-side crypto uses [tide-js](https://github.com/tide-foundation/tide-js), which consumers
install themselves. minidauth ships none of it.

## Governance

Roles are granted by a quorum, never by a single operator and never by your application.

A change is filed, approved to a threshold, and only then committed. On commit the ORK cohort signs
the attestation units that make the role real, and those signed units are what a doken is built from.
That last part matters more than it sounds: if minidauth rebuilt those units from local state at
sign-in time, anyone who could edit a file on the box could grant themselves anything. Signing once
and replaying the stored bytes means the file records what was agreed rather than deciding it.

Operators sign in to the console at `/console` with Tide. Nothing long-lived is stored anywhere; the
credential is a short-lived doken bound to that browser.

### What still depends on the machine

Owning the host still means holding the vendor root key, so it still means being able to act within
whatever policies are deployed. Signing grants at commit time removes silent forgery of arbitrary
roles; it does not remove key possession. Run minidauth somewhere separate from the application it
protects, and treat that host accordingly.

## Running it

```sh
export SYSTEM_HOME_ORK=http://localhost:1001
export PAYER_PUBLIC=...            # from your Tide network
export MC_PUBLIC_URL=https://minidauth.example   # how a browser reaches this service
./run.sh                           # listens on :8081
```

Then create the vendor key, which needs a Tide licence, and deploy an admin policy.

**Bootstrap order matters, and getting it wrong is not recoverable.** The VRK authorizer pack signs
exactly one policy and is then revoked by the network, and the same pack signs the attestation units
every doken needs. So the first admin has to sign in and be granted a role *before* the admin policy
is deployed. Deploy it first and you are left with a key that can no longer mint dokens.

## Licence

MIT. See [LICENSE](LICENSE) and [THIRD-PARTY.md](THIRD-PARTY.md), minidauth redistributes no
third-party code.

The Tide *licence* required by the vendor key lifecycle is a separate commercial arrangement with the
Tide Foundation and has nothing to do with the software licence above.
