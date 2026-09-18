#!/usr/bin/env bash
# Deploy the sealing policies and grant a demo reader role against a running minidauth, so an app
# can seal and open straight away. Idempotent: safe to re-run. See docs/sealing.md.
#
#   ./bootstrap.sh                 # against http://localhost:8081
#   MINIDAUTH_URL=... ./bootstrap.sh
set -euo pipefail
cd "$(dirname "$0")"

if command -v node >/dev/null 2>&1; then
  exec node bootstrap/bootstrap.mjs "$@"
fi
# No node on the host: run it in the sidecar image (which has node), on the host network so it can
# reach minidauth on localhost:8081 and read operators.json / keys from this repo.
exec docker run --rm --network host -v "$PWD:/repo" -w /repo \
  -e MINIDAUTH_URL="${MINIDAUTH_URL:-http://localhost:8081}" \
  -e DEMO_UID="${DEMO_UID:-1}" -e READER_ROLE="${READER_ROLE:-crm-reader}" \
  ghcr.io/sashyo/minidauth-seal:latest node bootstrap/bootstrap.mjs "$@"
