<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="minidauth" width="380">
  </picture>
</p>

<p align="center"><strong>Give your existing login a key that nobody holds.</strong></p>

<p align="center">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-111.svg"></a>
  <img alt="Java 17+" src="https://img.shields.io/badge/java-17%2B-111.svg">
  <img alt="115 tests passing" src="https://img.shields.io/badge/tests-115%20passing-111.svg">
</p>

Your app can already tell who someone is. What it cannot do is stop itself reading their data. The
database holds the rows, the app holds the key, and taking the machine takes both.

minidauth moves the key out. It exists only as shares spread across the [Tide](https://tide.org)
network, and no single node can reconstruct it. That key signs every token, policy and role grant
your system issues, and decides who may decrypt, and none of those decisions are your server's to
make. Your login stays exactly where it is: Cognito, Better Auth, Keycloak, Auth.js, whatever you
already run.

> **A stolen copy of your database contains nothing readable, and no key to make it readable.**

![minidauth in a minute](examples/notes/docs/demo.gif)

That is the [notes demo](examples/notes). No password, no user table, roles granted by a quorum, and
a database holding nothing but ciphertext.

The same key signs as well as encrypts, and signing is the busier half. Every sign-in token, every
policy, every role grant is an EdDSA signature produced jointly by a threshold of nodes. Nothing is
signed locally, which is why owning the server does not let you forge a role or mint a token the
network will accept.

It also means the network can refuse. Ask it to sign a payment over the limit its policy allows and
fourteen nodes independently decline, somewhere your code does not run. That is
[in the demo too](examples/notes#signing-which-encryption-cannot-do).

**[Try it](#quick-start)** in two commands, or read on for whether it is for you.

## What you actually get

| | |
|---|---|
| **A key that is never assembled** | Not "stored in an HSM", not "held by a service". It exists as shares, and a threshold of independent nodes cooperate to use it. There is no moment where the whole key exists. |
| **Every signature is a joint one** | Sign-in tokens, policies, role grants. Nothing minidauth issues is signed on your server, so taking the server does not let you forge a role or mint a token the network accepts. |
| **Identity you did not have to hold** | Sign-in happens in the ORKs' own enclave. No password reaches your application or this service, so there is none to leak. |
| **Role grants that need more than one person** | A grant is filed, approved by administrators in their own enclaves, and only then does the network sign the attestations that make it real. |
| **Reads decided by policy, not by your code** | The ORKs check the caller's role against a signed policy before they will help decrypt. Your app cannot decide to read; it can only ask. |
| **Your auth system untouched** | Store one extra column, a `vuid`, and add one callback route. |

Encryption is the visible one, and the easiest to check, which is why the demo leads with it. It is
not the whole of what the key does.

**Signing is the half that decides what may happen at all.** A custom request has its payload read by
the policy's contract before the cohort will sign, so the network can decline. The
[demo](examples/notes#signing-which-encryption-cannot-do) signs `amount=250;to=alice` and refuses
`amount=5000;to=alice`, with fourteen nodes independently answering "over the limit this policy will
sign". That refusal happens where your code does not run, so owning your server does not produce the
signature anyway. Approving a release, authorising a refund, issuing a credential: same shape.

## Quick start

```sh
curl -O https://raw.githubusercontent.com/sashyo/minidauth/main/docker-compose.yml
MC_ADMIN_TOKEN=$(openssl rand -hex 32) docker compose --profile public up
```

That pulls the image and runs it on :8081. No Java, no Maven, nothing to build. The image is
`linux/amd64`; on Apple Silicon Docker runs it under emulation.

**Why `--profile public`.** Sign-in happens inside the Tide enclave, a page served from the ORK's
own origin, and that page has to fetch a voucher back from this service. Browsers refuse a request
from a public page to a loopback address, so on a laptop the sign-in stops there. The profile starts
a `cloudflared` tunnel that gives the voucher endpoint an address the browser will accept. Only that
endpoint answers on it; the console, the ops routes and the governance API return 404 there, matched
on the host the request arrived on. Drop the profile if this service already has a public URL, and
set `MC_VOUCHER_PUBLIC_URL` to it instead.

Then [bring up a vendor key](docs/running.md#bringing-up-a-vendor-key), and open the
[notes demo](examples/notes) to watch it work.

### Building from source

The image carries Tide's `MidgardJava` jar, which Tide permits in a published image. Its source is
not public and is never part of this repository, so building yourself means getting the jar from the
[Tide Foundation](https://tide.org) and putting it in `vendor/`, which git ignores:

```sh
docker compose build                              # or, with a JDK 17+ and Maven:
mvn -q package -DskipTests && ./run.sh            # :8081
```

The jar's native library is built for `linux-x86-64` only, and the code imports it, which is also why
there is no CI here: a public runner cannot compile it.

Operator credentials live in `operators.json`, and an entry authenticates by token, token digest or
public key. [Running minidauth](docs/running.md) covers that, along with the order the first policies
must be deployed in and the mistakes that strand a key permanently.

## Who this is for

Not everybody. It earns its keep when **the data your app stores would be bad news in someone
else's hands, and you cannot honestly say your server is the last line of defence.**

**A small team holding data far heavier than the team.** Health records, legal files, financial
detail, anything under a regulator's eye. You do not have a security team, and you know one stolen
laptop or one leaked backup ends the conversation. This puts the reading decision somewhere your
laptop is not.

**A SaaS where insiders should not be able to browse customers.** Support needs to help; support
does not need to read. Today the difference is a code review and good intentions. Here it is a role
a quorum granted, and the network refuses without it.

**Anything with an admin panel that can read everything.** The most common breach is not a clever
exploit, it is a session token belonging to somebody with too much access. Take that session here and
you still cannot decrypt, because the token is not what the ORKs are checking.

**A side project you would rather not be liable for.** The cheapest way to never leak user data is
to be unable to read it.

**Not for you if** the data is public anyway, if you need to run analytics over plaintext server
side, or if you cannot tolerate a network hop on reads. Those are real costs and no amount of
cryptography talks you out of them.

## Honestly, what is proven

Everything above runs against the public Tide network, not a simulator:

- A value encrypted under a deployed policy and decrypted back through one gated on a role.
- A role grant refused by the network until an administrator approved it in their enclave.
- Sign-in, token minting with attested roles, key rotation and licensing.
- A payment instruction signed by the cohort, and one over the policy's limit refused by fourteen
  nodes independently.
- [Supabase](examples/supabase) and [Clerk](examples/clerk) apps linking their users to Tide
  identities and reading authorisation from the quorum, both recorded step by step. Better Auth the
  same, locally. Auth0 and Cognito share their minidauth code but have not been run against real
  accounts.

What is not: policy *deployment* is still gated by this service rather than the network, for a
reason explained under [governance](docs/running.md#governance).

The order you do things in matters more than anything else here, and getting it wrong strands the
key permanently. Follow the quick start in order and read "things that will bite you".

## The easy way into Tide

[Tide](https://tide.org) is a security fabric, not a login box. A network of independent nodes holds
key shares and will perform cryptography on your behalf without any of them, or you, ever holding a
whole key. Signing, encryption and the rules about who may do either are enforced by that network
rather than by your server.

The catch has always been the way in. Adopting it meant adopting
[TideCloak](https://github.com/tide-foundation/tidecloak), a Keycloak fork that does all of this
properly and completely, and replacing your identity system to get there. That is a big first step
for a team that just wants their database to stop being a single point of failure.

minidauth is the small door. It lifts the key lifecycle and the governance out of TideCloak and puts
them behind a plain HTTP service, so you keep the login you already have and add the fabric beside
it. One service, one extra column on your user table, one callback route.

What you get on the first day:

- A vendor key created, licensed and rotated on the Tide network, never assembled anywhere.
- Encryption and decryption gated by policies the network enforces.
- Role grants that a quorum approves and the network attests.

What the fabric gives you as you go further: signing your own payloads under policy, contracts that
decide what may be signed at all, and an offboarding path that is the only time keys are ever made
whole. If you grow into needing all of it, TideCloak is the full expression and this was never a
dead end, it is the same network and the same vendor key.

**The claim at the top is deliberately narrow.** Whoever runs minidauth holds the vendor key and can
ultimately authorise reads, and a quorum of your own operators can grant themselves the reading
role. Both are on purpose, because access has to be recoverable. What goes away is any *single*
party doing it alone, especially your application.

## How this differs from what you have

**A KMS or a vault** holds a key on your behalf and hands it over when your app asks. Compromise the
app and you get the plaintext, because the app is allowed to ask. minidauth's key is never handed
over, and the decision is made by nodes that are not yours.

**Client-side end to end encryption** gets the key away from the server but makes recovery and
sharing your problem. minidauth keeps recovery possible through a quorum, without any single party
being able to read alone.

**Envelope encryption in your app** still ends with a data key in the process that holds the data.

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

**[examples/notes](examples/notes) is the one to look at first.** Write a note, watch it get
encrypted inside the enclave, then read the database and find nothing but ciphertext. It is the
claim at the top of this file, made checkable in a page.

The rest are integrations, and the point of having several is that the minidauth half never
changes. It is the same file in all four. Authentication stays where it is; authorisation comes
from the grant record on every request rather than from the app's own database.

| | |
|---|---|
| [better-auth](examples/better-auth) | Runs locally, exercised against the live network |
| [supabase](examples/supabase) | Run end to end, with screenshots of the whole flow |
| [clerk](examples/clerk) | Run end to end, with screenshots of the whole flow |
| [auth0](examples/auth0) | Run end to end, with screenshots of the whole flow |
| [cognito](examples/cognito) | `npm run setup` builds the pool, but AWS wants a card |

Each one is three steps: store the vuid where the user cannot edit it, add a callback route, and
read roles rather than storing them. All four are written to avoid the same mistake, which is
putting roles in a token your own system can mint.

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

## Questions you are about to ask

**Does it slow everything down?** Reads that need decryption make a network call to a threshold of
nodes. Sign-in does too. Ordinary requests that touch no protected data are untouched. If every page
load decrypts something, you will feel it; if a handful of screens do, you will not.

**What if Tide disappears?** Offboarding exists for exactly this, and it is the one path where keys
are made whole again, deliberately. It is a property of the protocol rather than something minidauth
implements today, and worth reading about before you commit anything you cannot re-encrypt.

**What does it cost?** The vendor key needs a Tide licence, which is a subscription arranged with the
Tide Foundation. minidauth itself is MIT and free.

**Is it production ready?** No, and the [status section](#honestly-what-is-proven) says exactly what
has been run against the public network and what has not. Treat it as something to try rather than
something to depend on.

**Do I have to replace my login?** No, that is the entire point. Five [examples](examples) show the
same integration against different providers, and it is one column and one route in each.

## Governance, and what the network actually enforces

Roles are granted by a quorum, never by one operator and never by your application. A change is
filed, approved by administrators in their own enclaves, and only then does the network sign the
attestations that make the role real.

The distinction worth knowing before you trust any of it: some of that is enforced by the ORKs and
some by this service. [Running minidauth](docs/running.md#governance) has the table, including the
one thing still on the wrong side of the line and why it cannot be moved on an existing key.

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

MIT, see [LICENSE](LICENSE). The repository contains no third-party code; the published image
carries Tide's MidgardJava jar with their permission ([THIRD-PARTY.md](THIRD-PARTY.md)).

The Tide licence the vendor key requires is a separate commercial arrangement with the Tide
Foundation and has nothing to do with the software licence above.
