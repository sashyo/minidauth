# Turnkey field sealing

The one-command way to stand up everything an app needs to seal fields: minidauth, the sealing
sidecar, and a generated key pair. After this, an integration only sets `MINIDAUTH_SEAL_URL` and
mounts one key file. It is the same setup for every integration (Twenty, Cal.com, Formbricks,
Documenso, Medusa, Rocket.Chat, Chatwoot, Firefly III, Paperless-ngx).

The [README](../README.md) covers what minidauth is. [running.md](running.md) is the operator's
half. This page is the shortest path from nothing to a field sealing and opening.

## What you get

```
docker compose -f docker-compose.yml -f docker-compose.seal.yml up -d
```

brings up three things:

| | |
|---|---|
| **minidauth** | the service, on `http://localhost:8081`. Holds the vendor key as shares, never whole. |
| **sidecar** | the sealing service, on `http://localhost:3021`. Holds no key and no reader identity; it seals on `/seal` and opens on `/open` for a verified user the quorum granted the role. |
| **keygen** | runs once, writes `./keys/usertoken.key` (the app's signing key) and `./keys/authpub.b64` (the sidecar's verifying key). |

## The five steps

```sh
# 1. A quorum of operators (the dev tokens are fine to start).
cp operators.example.json operators.json

# 2. minidauth + sidecar + keys.
docker compose -f docker-compose.yml -f docker-compose.seal.yml up -d

# 3. Create a vendor key. This is the one step that needs a Tide licence and a browser; it is not
#    something a script can do for you. See running.md for the full ceremony.
curl -sX POST localhost:8081/vrk/create -H "Authorization: Bearer <ops>" \
  -H 'Content-Type: application/json' \
  -d '{"licensingTier":"FreeTier","email":"you@example.com","redirectUrl":"http://localhost:8081/console"}'
# ...pay, then call it again to finalize.

# 4. Deploy the sealing policies and grant a demo reader role. Idempotent, safe to re-run.
./bootstrap.sh

# 5. Point an app at the sidecar.
#    MINIDAUTH_SEAL_URL=http://localhost:3021
#    MINIDAUTH_SEAL_SIGNING_KEY_FILE=<this repo>/keys/usertoken.key
```

`bootstrap.sh` registers the two vault contracts, deploys the bootstrap / encrypt / decrypt
policies in the order that matters, and grants `crm-reader` to a demo user id. It skips anything
already in place, so running it twice is harmless. Set `DEMO_UID=` to skip the demo grant, or
`READER_ROLE=` to use a different role name.

## How an app uses it

Every integration is the same three env values and one shared key. The app signs a short-lived
Ed25519 token for its own signed-in user id; the sidecar verifies it with `authpub.b64` and asks
minidauth to open the field, which only happens if the quorum granted that user the reading role.

```sh
MINIDAUTH_SEAL_URL=http://localhost:3021
MINIDAUTH_SEAL_SIGNING_KEY_FILE=/path/to/keys/usertoken.key
```

Grant the role to a user and their sealed fields open; revoke it and the same reads go dark, with
no change to the app:

```sh
# grant crm-reader to app user 42 (tideless: keyed on the app's own user id)
DEMO_UID=42 ./bootstrap.sh
```

## What the key files are

| | |
|---|---|
| `keys/usertoken.key` | Ed25519 **private** key, PKCS8 PEM. The app mounts this and signs reader tokens with it. Keep it out of your repo. |
| `keys/authpub.b64` | Ed25519 **public** key, SPKI DER base64. The sidecar verifies tokens with it. Not a credential; safe to share. |

keygen writes both once and never rotates them on restart. Delete `keys/usertoken.key` and re-run
to rotate.

## Notes

- **The vendor key is the one manual step.** Creating it needs a Tide licence and a browser
  sign-in; nothing downstream of it is manual. `bootstrap.sh` refuses to proceed until the key
  exists and tells you how to create it.
- **operators.json is the quorum.** `bootstrap.sh` files each change as an operator, gathers the
  other operators' approvals, and commits. The example file's dev tokens work for a local run;
  replace them for anything real, and prefer `publicKey` operators (see running.md).
- **Sealed fields are opaque to search.** A sealed column cannot be matched by a `WHERE` or a
  full-text query, the same as for any field-level-encryption scheme. Keep the fields you look up
  on (emails, identifiers, amounts) in the clear.
