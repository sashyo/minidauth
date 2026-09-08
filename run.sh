#!/usr/bin/env bash
# Start minidauth, mini decentralised auth.
#
# SYSTEM_HOME_ORK / PAYER_PUBLIC / THRESHOLD_T / THRESHOLD_N describe the ORK network. When the
# local Tide stack is running they are read off the tidecloakP container, because a stack rebuild
# mints a new payer key and a hardcoded one goes stale silently (InitializeWallet answers 500 with
# "Payer <key> not found").
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

from_stack() {
  docker exec tidecloakP env 2>/dev/null | sed -n "s/^$1=//p" | head -1
}

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx tidecloakP; then
  : "${PAYER_PUBLIC:=$(from_stack PAYER_PUBLIC)}"
  : "${THRESHOLD_T:=$(from_stack THRESHOLD_T)}"
  : "${THRESHOLD_N:=$(from_stack THRESHOLD_N)}"
  # The container's SYSTEM_HOME_ORK is container-internal; reach the same ORK from the host.
  : "${SYSTEM_HOME_ORK:=http://localhost:1001}"
fi

export SYSTEM_HOME_ORK="${SYSTEM_HOME_ORK:-http://localhost:1001}"
# The payer's public key. Public by definition, so it is checked in rather than treated as a
# secret. This is the local development network's; point it at your own network's payer
# when you run against one.
export PAYER_PUBLIC="${PAYER_PUBLIC:-200000ceed4e0015d8c4d712943f1ce0dc95438ccfe1832d771cb6e16243871922ac1c}"
export THRESHOLD_T="${THRESHOLD_T:-14}"
export THRESHOLD_N="${THRESHOLD_N:-20}"
export MC_PORT="${MC_PORT:-8081}"
export MC_DATA_DIR="${MC_DATA_DIR:-$HERE/data}"
export MC_ADMIN_TOKEN="${MC_ADMIN_TOKEN:-dev-admin-token}"
export MC_OPERATORS_FILE="${MC_OPERATORS_FILE:-$HERE/operators.json}"
# Where the enclave fetches a voucher from, in the user's browser. Points at the WordPress proxy
# because issuing a voucher needs the VRK and draws on the licence's account quota, so the service
# will not hand them out unauthenticated. Making the console self-contained means solving that
# properly rather than opening the endpoint.
export MC_VOUCHER_URL="${MC_VOUCHER_URL:-http://localhost:8090/index.php?rest_route=/tide-ef/v1/vouchers}"
# Where a browser reaches this service, for the console's signed redirect URI.
export MC_PUBLIC_URL="${MC_PUBLIC_URL:-http://localhost:8081}"

echo "home ORK   : $SYSTEM_HOME_ORK"
echo "payer      : ${PAYER_PUBLIC:0:24}…"
echo "cohort     : T=$THRESHOLD_T N=$THRESHOLD_N"
exec java -jar "$HERE/target/minidauth.jar"
