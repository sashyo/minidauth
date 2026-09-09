# Running minidauth

Everything past `docker compose up`: bringing a vendor key to life, the order that matters, who may
approve what, and the things that will cost you an afternoon.

The [README](../README.md) covers what this is and how to try it. This is the operator's half.

## Bringing up a vendor key

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


## Operators and how they authenticate

**Why a token at all, when everything else signs in with Tide?** Because at this point nothing else
exists. There is no vendor key, so there is no enclave to sign in to and no roles to check against.
`MC_ADMIN_TOKEN` authorises exactly two calls, creating the key and signing the first enclave
settings. After a person has signed in and been granted `governance-admin`, the console and the API
take Tide sign-ins and the token has no further use. Stop exporting it.

For a real quorum before Tide admins exist, `cp operators.example.json operators.json` and list your
operators instead; with a single admin token the approval threshold is 1.

An entry authenticates in exactly one of three ways, strongest last:

| | |
|---|---|
| `token` | the token itself. Fine on a dev machine, a credential at rest |
| `tokenDigest` | its SHA-256, base64. The file stops being worth stealing |
| `publicKey` | an Ed25519 public key. Nothing here is a credential at all |

```sh
printf %s "$TOKEN" | openssl dgst -sha256 -binary | base64      # for tokenDigest
node examples/shared/keygen.js your-app                         # for publicKey
```

More than one is refused, because which is authoritative would be a guess, and guessing about
credentials is how the weaker one quietly stays usable.

**Prefer `publicKey` for applications.** The caller keeps a private key and proves it by signing a
short-lived assertion, sent as `Authorization: Assertion <jwt>`. There is then no shared secret
anywhere: a copy of this file grants nothing, and an assertion seen in transit is refused if replayed
and expires in a minute regardless. It is the same argument as the rest of the project, applied to
the one credential that was still a secret sitting in a file.

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


## Governance

Roles are granted by a quorum, never by one operator and never by your application. A change is
filed, approved to a threshold, then committed. On commit the Tide network signs the attestation
units that make the role real, and those signed units are what a token is later built from.

That last part is the whole design. If minidauth rebuilt those units from a local file at sign-in
time, anyone who could edit that file could grant themselves anything. Signing once and replaying
the stored bytes means the file records what was agreed instead of deciding it.

Operators sign in at `/console` with Tide. Nothing long-lived is stored anywhere.

### What the network enforces, and what this service does

Worth separating, because "approved" can mean two very different things.

| | decided by |
|---|---|
| who may decrypt | the ORKs, from the role in your doken, against the decrypt policy |
| which units may be signed at all | the ORKs, from the bootstrap contract |
| whether a role grant has enough approvals | the ORKs, from administrator dokens |
| whether a policy deployment has enough approvals | **this service** |

The console shows the two tallies in separate columns for this reason. "Operators" is counted here
and gates nothing against someone who owns the machine. "Admins" is counted by the network, from
dokens signed inside each administrator's own enclave.

Role grants get there through two policies over the same model, which is what makes the split hold
rather than depend on this service choosing honestly:

| | |
|---|---|
| bootstrap, IMPLICIT | signs the units every sign-in needs, refuses the two that confer a role |
| role-grants, EXPLICIT | signs *only* those two, and only with enough distinct administrators |

Name the wrong one and it fails in the contract. The bootstrap has to be IMPLICIT because
attestation units are signed on every sign-in, and demanding approvals there would mean no token
could ever be minted, including the administrators' own.

**Policy deployment is the one still on the wrong side of that line, and it cannot be moved on an
existing key.** The bootstrap must also cover `Policy:1` or nothing further could be deployed, and a
policy can only be rotated in place, never narrowed: the ORK's revoke-on-sign requires the
replacement to carry the same contract and the same models. So this service can always name the
IMPLICIT policy when deploying. Fixing it means teaching the bootstrap contract to refuse policies
that are not EXPLICIT, which has to be designed into the first policy of a fresh key.

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

**Signing your own payloads happens in the browser, not here.** A custom request routed through a
policy hands your bytes to the contract before the network signs, so a policy can refuse a payload it
does not recognise. The client libraries build that request and send it to the enclave, the same way
they do encryption; `heimdall-tide` is on npm and needs no vendoring. What minidauth cannot do is
build one server side, because the Java bindings cannot set a request name or draft. Either way it
needs a deployed policy, so the pack constraint above applies.

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


## Distributing an image

The quickest way to let somebody try minidauth is a published image: no Java, no Maven, no hunting
for a jar. `docker/publish.sh` builds and tags one. **Do not push it yet.**

The image contains `MidgardJava`, and that jar:

| | |
|---|---|
| carries no licence | no LICENSE, no NOTICE, nothing in the manifest, so all rights reserved |
| has no public source | `tide-foundation/Midgard` is a private repository |
| is not on Maven Central | there is no coordinate to depend on |
| contains only `linux-x86-64` | no macOS, no Windows, no arm64 |

Pushing that image to a registry redistributes Tide's code as surely as committing the jar would.
Ask them first. The ask is narrow, and worth separating into three:

1. **May we ship the jar inside a container image?** The smallest yes, and it unblocks every user.
2. **Could the jar carry a licence?** Right now its terms cannot be known by anybody who receives it.
3. **Could it go to Maven Central?** Then the dependency stops being a topic at all.

The contrast is worth putting in front of them: `tide-js` is a public repository under the Tide
Community Open Code License, and `@tideorg/js` and `heimdall-tide` are on npm. The browser half of
Tide is open and installable. The Java half is not, and this service is Java.

The same dependency is why there is no CI here. The code imports `org.midgard`, so a build without
the jar does not compile, and a public runner has no way to get it.
