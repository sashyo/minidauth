#!/bin/sh
# Start minidauth, and say the one thing that will otherwise waste an afternoon.
set -e

echo "home ORK   : $SYSTEM_HOME_ORK"
echo "cohort     : T=$THRESHOLD_T N=$THRESHOLD_N"
echo "data dir   : $MC_DATA_DIR"

# Sign-in runs in the ORK's enclave, on a public origin, and that page has to fetch a voucher back
# from this service. Browsers refuse a public page's request to a loopback address, so on a laptop
# the sign-in stops there unless the voucher endpoint has an address the browser will accept.
if [ -z "$MC_VOUCHER_PUBLIC_URL" ] && case "${MC_PUBLIC_URL:-}" in
     *localhost*|*127.0.0.1*|"") true ;; *) false ;; esac
then
  echo
  echo "Note: this service is on localhost, so the Tide enclave cannot fetch a voucher from it."
  echo "The browser blocks a public page reaching a loopback address, and sign-in stops there."
  echo "Either:"
  echo "  docker compose --profile public up   (publishes only the voucher endpoint, via cloudflared)"
  echo "  or set MC_VOUCHER_PUBLIC_URL to an address the browser can reach"
  echo
fi

exec java -jar /app/minidauth.jar
