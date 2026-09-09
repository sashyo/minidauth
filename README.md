# minidauth

**Mini decentralised auth.** A small service that gives your existing auth system a key nobody holds.

Keep your login where it is: Cognito, Better Auth, Keycloak, Auth.js, whatever you already run.
minidauth sits beside it and adds encryption whose key never exists in one place, plus a quorum that
decides who may decrypt.

Built on the [Tide protocol](https://tide.org), and distilled from
[TideCloak](https://github.com/tide-foundation/tidecloak), which does all of this inside a Keycloak
fork. minidauth lifts the key lifecycle and governance out of TideCloak so any auth system can use
them.

> **Status.** Identity, tokens, quorum governance and encryption all work against the public Tide
> network. A value has been encrypted under a deployed policy and decrypted back through one gated on
> a role. What is not yet enforced by the network is *who may approve a role grant*: today that is
> this service's own operator quorum rather than a policy the ORKs check. See "governance".
>
> The order you do things in matters more than anything else here, and getting it wrong strands the
> key permanently. Follow the quick start in order and read "things that will bite you".

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
cp /path/to/MidgardJava-1.0-SNAPSHOT.jar vendor/   # not on Maven Central, see below
MC_ADMIN_TOKEN=$(openssl rand -hex 32) docker compose --profile public up
```

That is the whole install. The image builds the service and runs it on :8081, and the `public`
profile publishes one endpoint, explained next.

**Why `--profile public`.** Sign-in happens inside the Tide enclave, a page served from the ORK's
own origin, and that page has to fetch a voucher back from this service. Browsers refuse a request
from a public page to a loopback address, so on a laptop the sign-in stops there. The profile starts
a `cloudflared` tunnel that gives the voucher endpoint an address the browser will accept. Only that
endpoint answers on it; the console, the ops routes and the governance API return 404 there, matched
on the host the request arrived on. Drop the profile if this service already has a public URL, and
set `MC_VOUCHER_PUBLIC_URL` to it instead.

**MidgardJava** is a Tide library, not on Maven Central and not redistributed here, so put the jar in
`vendor/` before building. The native library rides inside it, so nothing else is needed.

Without Docker, and with a JDK 17+ and Maven:

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
| `MC_POLICY_VERSION` | `3` |

`MC_POLICY_VERSION` exists because the bindings build policy version 4 and the released network
understands 3. Deploying without it fails with "Error with signing model: Policy:1", and the reason,
"Could not find specified policy version: 4", is in a response body the bindings discard.

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

**5. Deploy the policies.** In this order, and only after step 4, because signing the first policy
spends the VRK's authorizer pack and that pack is the only thing that can attest a role until a
policy exists. The service refuses the first deployment until somebody holds `governance-admin`,
because there is no way back from getting this wrong.

| | |
|---|---|
| bootstrap | `AttestationUnit:1` + `Policy:1`, IMPLICIT, PUBLIC |
| encrypt | `PolicyEnabledEncryption:1`, IMPLICIT, PUBLIC |
| decrypt | `PolicyEnabledDecryption:1`, IMPLICIT, PRIVATE, `params.role` |

The bootstrap has to cover both models: units alone means no further policies, `Policy:1` alone means
no tokens. Its contract refuses the two unit types that confer a role, so the policy that replaces
the pack cannot be used to hand anybody one.

**6. Encrypt and decrypt.** Open `/console/vault`, which runs one of each through the enclave. This
is a test harness rather than product UI, and it is the shortest way to see the whole chain work.

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

### What the network enforces, and what this service does

Worth separating, because the console does not yet make the difference obvious.

| | decided by |
|---|---|
| who may decrypt | the ORKs, from the role in your doken, against the deployed decrypt policy |
| which units may be signed at all | the ORKs, from the bootstrap contract |
| whether a role grant has enough approvals | **this service** |
| whether a policy deployment has enough approvals | **this service** |

The first two are cryptographic: a compromised host cannot decrypt without a role, and cannot sign
the units that would grant itself one. The last two are not. They are checked here, by this process,
against the approval threshold, so someone who owns the machine can approve their own change.

Closing that means an EXPLICIT policy over `AttestationUnit:1` whose contract counts admin dokens,
with role units routed to it, and the same for `Policy:1`. The bootstrap policy is IMPLICIT precisely
because it cannot be: attestation units are signed on every sign-in, and a policy demanding approvals
for those means no token can ever be minted, including the admin tokens it is waiting for. Breaking
that circle is the remaining work.

## Things that will bite you

**The first policy you deploy decides what the key can do afterwards.** The VRK's authorizer pack
signs exactly one policy and the network then revokes it. That pack also signs attestation units,
which every token needs, so a badly scoped first policy leaves a key that cannot mint tokens, or one
that cannot deploy anything further.

Both problems have the same fix, because `AttestationUnit:1` and `Policy:1` each accept a policy as
their authoriser. Make the first policy cover both, for example with the `any` wildcard, and the key
keeps working: token minting moves onto the policy, and further policies can still be deployed. This
is verified, a key with a policy deployed still mints tokens.

Scope that first policy too narrowly and you are stuck. A policy over `AttestationUnit:1` alone
keeps tokens working but cannot authorise deploying anything else.

**Encryption runs in the browser, not here.** The Java bindings do expose local encrypt and decrypt
calls, but they take a complete private key and make no network calls at all, so they belong to
deployments that have reconstructed their key and left the network. This service does not use them
and should not. The real route is a policy, applied inside the enclave, which is what `/console/vault`
demonstrates.

**A browser will not let the enclave reach localhost.** Sign-in happens on the ORK's public origin
and that page has to fetch a voucher back from this service; browsers refuse a public page's request
to a loopback address, and it surfaces as a bare network failure. Run `docker compose --profile
public up`, or point `MC_VOUCHER_PUBLIC_URL` at an address the browser will accept. A deployed
service on a public URL never meets this.

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
