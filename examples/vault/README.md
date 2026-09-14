# Vault — a confidential records desk on Supabase + minidauth

A small firm's client vault. Staff sign in with Supabase; sensitive fields (bank, tax id, private
notes) are **sealed in the browser via the Tide network before they ever reach the database**, and
revealed only for a user whose id holds a quorum-granted role. Releases are **network-signed** — real
only if the cohort signed the instruction, and refused over the policy's limit.

It is **tideless**: no second login, no Tide account, no doken. The Supabase user id is the subject,
and a role a quorum granted it is the gate.

![Vault records](docs/demo.png)

| | |
|---|---|
| Reveal a field | ![reveal](docs/reveal.png) |
| What the database actually holds | ![raw](docs/raw.png) |

## What it shows

- **Encrypted at rest, for real.** Every sensitive field is ciphertext the ORK cohort sealed. The
  *Raw store* view is exactly what a `pg_dump` or a stolen service-role key returns: no plaintext, and
  no key anywhere to make it readable.
- **Reads gated by a quorum-granted role, not by the app.** Revealing a field asks minidauth for a
  decrypt voucher; minidauth issues it only if the signed-in user's id holds `vault-reader` — a role a
  quorum granted. The app cannot grant itself one.
- **Actions the network signs.** A release is signed by the cohort under a policy contract that reads
  the amount and refuses over the limit. Anyone can verify the signature with the vendor public key.
- **No second login.** All of it runs off the Supabase session; the browser holds no Tide credential.

## How the crypto works (no doken)

The browser runs the real Tide flows (`@tideorg/js`) with a **guest session key** instead of a doken —
the flows fall back to a plain `gSessKey` when no token is present. What authorises each operation is a
**voucher**, and the server issues vouchers through [`../shared/minidauth.js`](../shared/minidauth.js):

| browser → server | server → minidauth | gate |
|---|---|---|
| `/api/vault/voucher/sign` | `POST /tide/vouchers` | any signed-in user may seal a field |
| `/api/vault/voucher/decrypt` | `POST /vault/voucher {uid, role}` | **the user's id must hold the role** |

The uid on the decrypt side is taken from the verified Supabase session, never from the browser, so a
page cannot voucher a read for another user. See [examples/tideless](../tideless) for the bare round
trip and its trade-off (minidauth becomes the read authority for these users).

## Run it

Needs minidauth up with a vendor key, an encrypt policy, and a **PUBLIC** decrypt policy (voucher-gated;
see [docs/running.md](../../docs/running.md)).

1. **Supabase.** Create a project, run [`schema.sql`](schema.sql) in the SQL editor, and grant your
   Supabase user id the role through the quorum:

   ```sh
   curl -sX POST localhost:8081/iga/change-requests/role -H "Authorization: Bearer $ALICE" \
     -H 'Content-Type: application/json' -d '{"vuid":"<your supabase user id>","role":"vault-reader","tideless":true}'
   # $BOB and $CAROL authorize, then commit
   ```

2. **Start it.**

   ```sh
   npm install
   cat > .env <<'EOF'
   SUPABASE_URL=https://<project>.supabase.co
   SUPABASE_ANON_KEY=<publishable key>
   SUPABASE_SERVICE_ROLE_KEY=<secret key>
   MINIDAUTH_URL=http://localhost:8081
   MINIDAUTH_TOKEN=<relying-party token>
   EOF
   npm start          # http://localhost:3007
   ```

Open it **without** Supabase configured and it runs in **demo mode** — example records, simulated
reveal and sign — so you can explore the UI before wiring anything up.
