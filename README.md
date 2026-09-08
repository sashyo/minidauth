# minidauth

**Mini decentralised auth.** A small service that gives your existing auth system a key nobody holds.

Keep your login where it is: Cognito, Better Auth, Keycloak, Auth.js, whatever you already run.
minidauth sits beside it and adds encryption whose key never exists in one place, plus a quorum that
decides who may decrypt.

Built on the [Tide protocol](https://tide.org), and distilled from
[TideCloak](https://github.com/tide-foundation/tidecloak), which does all of this inside a Keycloak
fork. minidauth lifts the key lifecycle and governance out of Keycloak so any auth system can use
them.

## Why

Your app can already tell who someone is. What it cannot do is stop itself reading their data: the
database holds the rows, the app holds the key, and taking the machine takes both.

minidauth moves the key out. It exists only as shares spread across the Tide network, no single node
can reconstruct it, and decryption is authorised by a policy the network enforces.

> **A stolen copy of your database contains nothing readable, and no key to make it readable.**

That claim is deliberately narrow. Whoever runs minidauth holds the vendor key and can ultimately
authorise reads, and a quorum of your own operators can grant themselves the reading role. Both are
on purpose, because access has to be recoverable. What goes away is any *single* party doing it
alone, especially your application.

## Quick start

```sh
cp operators.example.json operators.json     # edit the tokens
export MC_ADMIN_TOKEN=$(openssl rand -hex 32)
export MC_PUBLIC_URL=http://localhost:8081   # how a browser reaches this service
mvn -q package -DskipTests && ./run.sh       # :8081
```

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

**4. Grant the first role,** through the quorum. This is the only step that uses operator tokens.

```sh
CR=$(curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
  -H 'Content-Type: application/json' -d "{\"vuid\":\"$VUID\",\"role\":\"vault-reader\"}" | jq -r .id)

curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $BOB"
curl -sX POST localhost:8081/iga/change-requests/$CR/authorize -H "Authorization: Bearer $CAROL"
curl -sX POST localhost:8081/iga/change-requests/$CR/commit    -H "Authorization: Bearer $ALICE"
```

Repeat for `vault-writer`, and `governance-admin` for anyone who should administer.

**5. Encrypt and decrypt.** Sign in again so the token carries the new roles.

```sh
curl -sX POST localhost:8081/vault/encrypt -H "Authorization: Doken $DOKEN" \
  -H 'Content-Type: application/json' -d '{"data":"a secret"}'

curl -sX POST localhost:8081/vault/decrypt -H "Authorization: Doken $DOKEN" \
  -H 'Content-Type: application/json' -d '{"encrypted":"..."}'
```

Without the role, 403. That refusal is the product working.

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

| | |
|---|---|
| `POST /tide/enclave/login-url` | where to send the user |
| `POST /tide/enclave/callback` | returns `{ vuid, doken, roles }` |
| `GET /iga/grants/{vuid}` | what that identity holds |
| `POST /vault/encrypt` and `/vault/decrypt` | the data operations |

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

**Deploying a policy stops the key minting tokens.** `Policy:1` and `AttestationUnit:1` share one
authorizer pack, the network revokes that pack when it signs a policy, and every token needs
`AttestationUnit:1`. If you only need `/vault/encrypt` and `/vault/decrypt`, deploy no policy and the
key works indefinitely. Policies are only needed for anonymous encryption, where the writer has no
identity.

**Tide accounts outlive your vendor key.** They live on the network, so deleting the key and starting
again does not reset your users, and reusing a username returns 409.

**Owning the host still means holding the vendor key.** Signed grants stop silent forgery of roles;
they do not stop someone with the machine acting within deployed policies.

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
