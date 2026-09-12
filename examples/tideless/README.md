# tideless — encrypt, sign and decrypt for users with no Tide account

Every other example links a Tide identity to each user. This one does not. The "user" is just an id
your app already has, and a quorum has granted that id a role through minidauth. The user never signs
in to Tide and never holds a doken; minidauth acts on their behalf and the gate is the role.

This is the mode for regular users who should read their own data, or request signed actions, without
a second login — while the accounts that can read *everyone's* data still get real Tide identities.

## What it proves

[`roundtrip.mjs`](roundtrip.mjs) runs, against the live Tide network, a full encrypt → decrypt for a
no-account user:

- **encrypt** authorised only by a `vendorsign` voucher minidauth mints, gSessKey, no doken
- **decrypt** authorised only by a `vendordecrypt` voucher from the role-gated `/vault/voucher`, again
  no doken
- the cohort does the threshold crypto; the vendor key is never assembled

## The trade you are making

minidauth becomes the **authority** for these users' reads and signatures: it decides from a
quorum-approved grant record, rather than the cohort checking a doken. What you keep is that roles are
granted and revoked by the quorum and the key is never whole; what you give up is the per-request
cryptographic proof that this specific caller holds the role — you are trusting your app server to say
who is calling. That is the right trade when a second login is not worth it and the app server is
already trusted. When it is not, link a Tide identity instead (see the other examples).

## The three endpoints

| | |
|---|---|
| `POST /iga/change-requests/role` `{vuid, role, tideless: true}` | grant a role to an app user id, through the file → approve → commit quorum. No attestation — there is no identity to attest. |
| `POST /vault/sign` `{uid, role, payload}` | minidauth checks the grant, then the cohort signs. Returns a VVK signature anyone can verify with the vendor public key. |
| `POST /vault/voucher` `{uid, role, voucherRequest}` | issues a decrypt voucher only if the user holds the role; the client then decrypts with it. |

`/vault/sign` is turnkey — the cohort's contract still enforces the payload rule (e.g. a payment
limit), so even here an over-limit sign is refused by the network.

## Running the round trip

1. Bring up minidauth with a vendor key and the policies deployed, including a **PUBLIC** decrypt
   policy (`executionType: PUBLIC`) so a voucher, not a doken, gates the read. See the
   [operator guide](../../docs/running.md).

2. Grant a tideless user a role, through the quorum:

   ```sh
   curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
     -H 'Content-Type: application/json' -d '{"vuid":"user_123","role":"vault-reader","tideless":true}'
   # then $BOB and $CAROL authorize, then commit — same as any governed change
   ```

3. Install and run:

   ```sh
   npm install
   APP_UID=user_123 ROLE=vault-reader node --import ./register.mjs roundtrip.mjs
   ```

   Expected tail: `TIDELESS ROUND TRIP OK`.

## No fork needed

Two things make this work with the published SDK:

- **The published `@tideorg/js` is built for the 14-of-20 network** (`Threshold = 14`, `Max = 20`),
  so it drives the live network out of the box. Only if you target a network with different numbers
  do you need a build to match — point `TIDE_JS_DIST` at it. (Making T/N runtime-configurable, from
  the key info minidauth already has, is tracked upstream.)
- **The doken-less path uses the SDK's existing gSessKey mode.** The flows send a `gSessKey` when no
  token is present; `roundtrip.mjs` reaches that with a small guest-doken stub (`serialize()` → `""`).
  A first-class guest flow upstream would replace the stub.
