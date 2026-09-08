# minidauth

**Mini decentralised auth.** A small service that gives your existing auth system a key nobody holds.

Keep your login where it is: Cognito, Better Auth, Keycloak, Auth.js, whatever you already run.
minidauth sits beside it and adds encryption whose key never exists in one place, plus a quorum that
decides who may decrypt.

Built on the [Tide protocol](https://tide.org), and distilled from
[TideCloak](https://github.com/tide-foundation/tidecloak), which does all of this inside a Keycloak
fork. minidauth lifts the key lifecycle and governance out of TideCloak so any auth system can use
them.

> **Status.** Identity, tokens and quorum governance work and are exercised against a live Tide
> network. Encryption is not usable end to end yet: it needs a deployed policy, and deploying one
> currently stops the key minting tokens. Details under "things that will bite you".

## Why

Your app can already tell who someone is. What it cannot do is stop itself reading their data: the
database holds the rows, the app holds the key, and taking the machine takes both.

minidauth moves the key out. It exists only as shares spread across the Tide network, no single node
can reconstruct it, and decryption is authorised by a policy the network enforces.

The same key **signs** as well as encrypts, and signing is the busier half. Every sign-in token,
every policy, every role grant and every settings change is an EdDSA signature produced jointly by a
threshold of nodes. Nothing minidauth issues is signed locally, which is why a compromised host
cannot forge a role or mint a token that the network will accept.

> **A stolen copy of your database contains nothing readable, and no key to make it readable.**

That claim is deliberately narrow. Whoever runs minidauth holds the vendor key and can ultimately
authorise reads, and a quorum of your own operators can grant themselves the reading role. Both are
on purpose, because access has to be recoverable. What goes away is any *single* party doing it
alone, especially your application.

## Quick start

```sh
export MC_ADMIN_TOKEN=$(openssl rand -hex 32)   # bootstrap only, see below
export MC_PUBLIC_URL=http://localhost:8081      # how a browser reaches this service
mvn -q package -DskipTests && ./run.sh          # :8081
```

**Why a token at all, when everything else signs in with Tide?** Because at this point nothing else
exists. There is no vendor key, so there is no enclave to sign in to and no roles to check against.
`MC_ADMIN_TOKEN` authorises exactly two calls, creating the key and signing the first enclave
settings. After a person has signed in and been granted `governance-admin`, the console and the API
take Tide sign-ins and the token has no further use. Stop exporting it.

For a real quorum before Tide admins exist, `cp operators.example.json operators.json` and list your
operators instead; with a single admin token the approval threshold is 1.

Defaults point at the public Tide network, so there is nothing else to configure:

| | |
|---|---|
| `SYSTEM_HOME_ORK` | `https://ork1.tideprotocol.com` |
| `PAYER_PUBLIC` | `200000b967a7799ffd4476e1074777ebc83bec23a3843cb2e5ca43c83561802c8e646b` |
| `THRESHOLD_T` / `THRESHOLD_N` | 14 of 20 |

`PAYER_PUBLIC` must match the network in `SYSTEM_HOME_ORK`, or you get "Payer &lt;key&gt; not found"
and no other clue.

**1. Create the vendor key.** Needs a Tide licence, which is a Stripe subscription. The first call
returns a checkout URL; call it again after paying to finalize.

```sh
curl -sX POST localhost:8081/vrk/create -H "Authorization: Bearer $OPS" \
  -H 'Content-Type: application/json' \
  -d '{"licensingTier":"FreeTier","email":"you@example.com","redirectUrl":"http://localhost:8081/console"}'
```

**2. Sign the enclave settings.** The enclave will not return to a URI it has no signature for.

```sh
curl -sX POST localhost:8081/tide/enclave/settings -H "Authorization: Bearer $OPS" \
  -H 'Content-Type: application/json' -d '{
    "regOn": true, "backupOn": false,
    "logoUrl": "https://yourapp.example/logo.png",
    "imageUrl": "https://yourapp.example/bg.png",
    "redirectUris": ["http://localhost:8081/console"],
    "clientOrigins": ["http://localhost:8081"]
  }'
```

`logoUrl` and `imageUrl` are required and must be real URLs, even though they only brand the sign-in
screen.

**3. Sign in.** Open `http://localhost:8081/console` and use *Sign in with Tide*. It will say you
have no governance role, which is right, since nobody does yet. Note your `vuid`.

**4. Grant the first role,** through the quorum. The last step that needs the bootstrap token.

```sh
CR=$(curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d "{\"vuid\":\"$VUID\",\"role\":\"vault-reader\"}" | jq -r .id)

curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $BOB"
curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $CAROL"
curl -sX POST localhost:8081/iga/change-requests/$CR/commit    -H "Authorization: Bearer $ALICE"
```

Repeat for `vault-writer`, and `governance-admin` for anyone who should administer.

**5. Encrypt and decrypt.** Not yet, and this is the honest state of the project. See below.

## How it fits

```
                    ┌────────────────────┐
                    │   user's browser   │
                    └──┬──────────────┬──┘
        normal login   │              │   Tide sign-in runs
                       ▼              ▼   in the enclave
   ┌───────────────────────────┐      ╎
   │     your app + auth       │      ╎    ┌──────────────────────┐
   │  Cognito / Better Auth /  │─────────▶ │      minidauth       │
   │  Keycloak / Auth.js       │      ╎    │  vendor key          │
   │                           │ ◀───────  │  policies            │
   │  owns users and sessions  │      ╎    │  governance quorum   │
   │  stores one column: vuid  │      ╎    │  console             │
   └───────────────────────────┘      ╎    └──────────┬───────────┘
                                      ╎               ▼
      never talks to the network ╌╌╌╌╌╎        Tide ORK network
                                            key shares, enforces policy
```

Your app talks only to minidauth, over ordinary HTTP. It never touches the Tide network and never
holds anything that can grant a role, which is why the governance console is served here rather than
embedded in your admin panel.

**Run minidauth on a different machine from the app it protects.** The app is what you assume gets
compromised; the key must not be there.

## Wiring it to your auth system

Same three steps everywhere: store a `vuid` against your user, add a route that finishes the Tide
sign-in, and read authorisation from grants rather than from your own tables.

> **Status:** the endpoints below are exercised against a live Tide network. The per-system notes
> that follow are written from that API surface, not from shipped integrations: there is no Cognito
> or Better Auth sample app yet. Treat them as the intended shape, not as a tested recipe.

| | |
|---|---|
| `POST /tide/enclave/login-url` | where to send the user |
| `POST /tide/enclave/callback` | returns `{ vuid, doken, roles }` |
| `GET /iga/grants/{vuid}` | what that identity holds |
| `GET /vault/encrypt-policy` | the public policy a browser needs in order to encrypt |

Signing is not an endpoint you call. It happens inside the operations above: the token you receive,
and the grants behind it, are already signed by a threshold of nodes.

**Cognito.** Add `custom:tide_vuid` to the user pool and write the vuid there after sign-in. A Pre
Token Generation trigger can copy the vuid into the token, but copy **only** the vuid. A role that
arrives via a Cognito trigger is a role your AWS account can mint, which puts you back where you
started.

**Better Auth.** Add `tideVuid` to the user table, complete the callback in a plugin endpoint, and
keep the doken in the session rather than the database.

**Anything else.** Same pattern. If you cannot add a column, key the mapping on whatever stable id
the app already has.

**One constraint:** dokens are EdDSA. Node's `jsonwebtoken` cannot verify Ed25519 and neither can
stock .NET, so on those stacks verify through minidauth instead of locally.

## Governance

Roles are granted by a quorum, never by one operator and never by your application. A change is
filed, approved to a threshold, then committed. On commit the Tide network signs the attestation
units that make the role real, and those signed units are what a token is later built from.

That last part is the whole design. If minidauth rebuilt those units from a local file at sign-in
time, anyone who could edit that file could grant themselves anything. Signing once and replaying
the stored bytes means the file records what was agreed instead of deciding it.

Operators sign in at `/console` with Tide. Nothing long-lived is stored anywhere.

## Things that will bite you

**Encryption is not usable end to end yet.** Identity, tokens and governance work and are exercised
against a live network. Encryption is not, and the reason is worth knowing before you plan around it.
The only route that does not require assembling the key is the policy route, which runs in the
browser with tide-js, and that needs a deployed policy. The Java bindings do expose local encrypt and
decrypt calls, but they take a complete private key and do no network work at all, so they belong to
deployments that have already reconstructed their key and left the network. This service does not use
them and should not.

**Deploying a policy stops the key minting tokens.** `Policy:1` and `AttestationUnit:1` share one
authorizer pack, the network revokes that pack when it signs a policy, and every token needs
`AttestationUnit:1`. So a key can currently mint tokens or authorise encryption, and not both. That is the
main thing standing between this and a working demonstration.

**Tide accounts outlive your vendor key.** They live on the network, so deleting the key and starting
again does not reset your users, and reusing a username returns 409.

**Owning the host still means holding the vendor key.** Signed grants stop silent forgery of roles;
they do not stop someone with the machine acting within deployed policies.

**Signing your own payloads goes through tide-js, and needs a policy.** A custom request routed
through a policy hands your bytes to the contract before the network signs, so a policy can refuse a
payload it does not recognise. tide-js can build that request today; minidauth cannot, because the
Java bindings cannot set a request name or draft. Either way it needs a deployed policy, so the
pack constraint above applies.

Do not reach for the local signing call in the Java bindings. It takes a fully reconstructed private
key and exists only for realms that have left Tide, so using it would put a whole key in this
process and give up the one property that matters.

## Vocabulary

| | |
|---|---|
| **VRK** | Vendor *rotating* key. Authorises this service to the network. Rotation is routine, not incident response. |
| **VVK** | Vendor key. What data is encrypted to. Exists only as shares, never assembled. |
| **ORK** | A node in the Tide network. A threshold of them can act; none alone can. |
| **doken** | Short-lived token the network signs after sign-in, carrying attested roles. EdDSA. |
| **policy** | Signed rules the network enforces. Names the operations it allows and cannot be used for others. |

Rotating the VRK does not touch stored data, because data is encrypted to the VVK. The two are easy
to confuse and the difference is expensive.

## Licence

MIT, see [LICENSE](LICENSE). minidauth redistributes no third-party code
([THIRD-PARTY.md](THIRD-PARTY.md)).

The Tide licence the vendor key requires is a separate commercial arrangement with the Tide
Foundation and has nothing to do with the software licence above.
