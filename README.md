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

It is not a claim that nobody can read the data. minidauth holds the vendor rotating key, so whoever runs
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

Owning the host still means holding the vendor rotating key, so it still means being able to act within
whatever policies are deployed. Signing grants at commit time removes silent forgery of arbitrary
roles; it does not remove key possession. Run minidauth somewhere separate from the application it
protects, and treat that host accordingly.

## Vocabulary

Tide's terms, briefly, because they are not guessable and the names carry meaning.

| | |
|---|---|
| **VRK** | Vendor *rotating* key. What authorises this service to ask the network for things. It rotates, hence the name, and rotation is a normal part of the lifecycle rather than an incident response. |
| **VVK** | Vendor key. The one data is encrypted to. It exists only as shares across the ORK network and is never assembled. |
| **ORK** | A node in the Tide network. Each holds a share; a threshold of them together can act, none alone can. |
| **doken** | A short-lived token the cohort signs after a Tide sign-in, bound to a key held inside the enclave. Carries the roles the network attested. EdDSA. |
| **policy** | Signed rules the network enforces about who may do what. A policy names the models it authorises and cannot be used for anything else. |
| **attestation unit** | A signed statement of fact the network checks a token against. A role only counts if a unit vouches for it. |

The VRK and the VVK are easy to confuse and the difference matters: rotating the VRK does not touch
stored data, because the data is encrypted to the VVK.

## Running it

### 1. Point it at a network

Defaults are the public Tide network, so a clean clone needs no configuration:

| | |
|---|---|
| `SYSTEM_HOME_ORK` | `https://ork1.tideprotocol.com` |
| `PAYER_PUBLIC` | `200000b967a7799ffd4476e1074777ebc83bec23a3843cb2e5ca43c83561802c8e646b` |
| `THRESHOLD_T` / `THRESHOLD_N` | `14` of `20` |

`PAYER_PUBLIC` must belong to the same network as `SYSTEM_HOME_ORK`. Mismatch them and
`InitializeWallet` answers 500 with "Payer &lt;key&gt; not found", which is all the diagnosis you get.
If a local dev stack is running, `run.sh` detects it and uses its values instead.

```sh
export MC_PUBLIC_URL=http://localhost:8081   # how a browser reaches this service
export MC_ADMIN_TOKEN=$(openssl rand -hex 32)
cp operators.example.json operators.json     # then edit the tokens
mvn -q package -DskipTests
./run.sh                                     # :8081
```

### 2. Create the vendor key

Needs a Tide licence, which is a Stripe subscription. The first call returns a checkout URL; the
second finalizes once payment has landed.

```sh
curl -sX POST localhost:8081/vrk/create -H "Authorization: Bearer $OPS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"licensingTier":"FreeTier","email":"you@example.com","redirectUrl":"http://localhost:8081/console"}'
# -> {"state":"AwaitingPayment","checkoutUrl":"https://checkout.stripe.com/..."}

# open the checkout URL, subscribe, then:
curl -sX POST localhost:8081/vrk/create -H "Authorization: Bearer $OPS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"licensingTier":"FreeTier","email":"you@example.com","redirectUrl":"http://localhost:8081/console"}'
# -> {"state":"Created","vvkId":"e2ca6be1-..."}
```

### 3. Sign the enclave settings

The enclave refuses to return to a URI it has no signature for, so register them before anyone signs
in. Include the console itself.

```sh
curl -sX POST localhost:8081/tide/enclave/settings -H "Authorization: Bearer $OPS_TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "regOn": true, "backupOn": false,
    "logoUrl":  "https://yourapp.example/logo.png",
    "imageUrl": "https://yourapp.example/bg.png",
    "redirectUris": ["http://localhost:8081/console", "https://yourapp.example/tide-callback"],
    "clientOrigins": ["http://localhost:8081", "https://yourapp.example"]
  }'
```

`logoUrl` and `imageUrl` are required and must parse as URLs, even though they are only branding for
the sign-in screen. Omit them and the network refuses the whole ceremony with "Image URL in vSettings
is not a valid url", surfaced here as a bare 500.

### 4. Sign in as the first operator

Open `http://localhost:8081/console` and use **Sign in with Tide**. You will be told you have no
governance role, which is correct: nobody has one yet. Note the `vuid` it shows.

Tide accounts live on the ORK network, not with your vendor key. Deleting the key and starting over
does not delete your users, and creating an account with a name you used before returns 409.

### 5. Grant the first roles

Through the quorum, using operator tokens. This is the only step that uses them; after it, operators
sign in with Tide.

```sh
VUID=<from the console>

CR=$(curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' \
  -d "{\"vuid\":\"$VUID\",\"role\":\"vault-reader\"}" | jq -r .id)

curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $BOB"
curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $CAROL"
curl -sX POST localhost:8081/iga/change-requests/$CR/commit    -H "Authorization: Bearer $ALICE"
```

On commit the cohort signs the attestation units that make the role real. If the network will not
sign, the grant does not happen: there is no path that records a role this service cannot prove.

Repeat for `vault-writer`, and for `governance-admin` if this operator should administer.

### 6. Encrypt and decrypt

Sign in again so the doken carries the new roles, then:

```sh
curl -sX POST localhost:8081/vault/encrypt -H "Authorization: Doken $DOKEN" \
  -H 'Content-Type: application/json' -d '{"data":"a secret"}'
# -> {"encrypted":"..."}

curl -sX POST localhost:8081/vault/decrypt -H "Authorization: Doken $DOKEN" \
  -H 'Content-Type: application/json' -d '{"encrypted":"..."}'
# -> {"data":"a secret"}
```

Without the role you get 403, and the message says roles are granted through the quorum rather than
by this service. That refusal is the product working.

### The one ordering trap

`Policy:1` and `AttestationUnit:1` sit on the same VRK authorizer pack. The network revokes that pack
the moment it signs a policy, and `AttestationUnit:1` is what every doken needs. So:

**Deploying a policy stops the key minting dokens.**

If you only need `/vault/encrypt` and `/vault/decrypt`, deploy no policy at all and the key keeps
working indefinitely. That is the recommended shape today.

Policies are needed only for anonymous encryption, where a writer has no identity. Getting both on
one key requires signing attestation units through a policy rather than through the pack, which the
Java bindings cannot currently express.

## Licence

MIT. See [LICENSE](LICENSE) and [THIRD-PARTY.md](THIRD-PARTY.md), minidauth redistributes no
third-party code.

The Tide *licence* required by the vendor key lifecycle is a separate commercial arrangement with the
Tide Foundation and has nothing to do with the software licence above.
