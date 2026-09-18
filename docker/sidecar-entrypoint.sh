#!/bin/sh
# Start the sealing sidecar. The keygen service writes the app keypair into the shared volume before
# this runs; here we read the PUBLIC half and hand it to the sidecar, which uses it to verify the
# short-lived reader tokens each app signs with the private half. No secret is baked into the image.
set -e

PUB_FILE="${MINIDAUTH_AUTH_PUBLIC_KEY_FILE:-/keys/authpub.b64}"
if [ -z "${MINIDAUTH_AUTH_PUBLIC_KEY:-}" ] && [ -f "$PUB_FILE" ]; then
  MINIDAUTH_AUTH_PUBLIC_KEY="$(cat "$PUB_FILE")"
  export MINIDAUTH_AUTH_PUBLIC_KEY
fi

: "${PORT:=3021}"
: "${MINIDAUTH_URL:=http://minidauth:8081}"
: "${MINIDAUTH_READER_ROLE:=crm-reader}"
: "${MINIDAUTH_ALLOW_SERVER_OPEN:=true}"
: "${MINIDAUTH_AUTH_MODE:=eddsa}"
: "${MINIDAUTH_AUTH_UID_CLAIM:=sub}"
export PORT MINIDAUTH_URL MINIDAUTH_READER_ROLE MINIDAUTH_ALLOW_SERVER_OPEN MINIDAUTH_AUTH_MODE MINIDAUTH_AUTH_UID_CLAIM

echo "minidauth-seal sidecar: port $PORT -> minidauth $MINIDAUTH_URL, role $MINIDAUTH_READER_ROLE"
exec node --import ./register.mjs server.mjs
