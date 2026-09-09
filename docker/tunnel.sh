#!/bin/sh
# Publish the voucher endpoint and record the address.
#
# The service reads /tunnel/url when it needs to tell the enclave where to fetch a voucher, so
# writing the file is the whole handshake. Written only once cloudflared reports a URL, so a
# half-started tunnel never looks like a working one.
set -e

TARGET="${TUNNEL_TARGET:-http://minidauth:8081}"
OUT="${TUNNEL_URL_FILE:-/tunnel/url}"
rm -f "$OUT"

echo "publishing $TARGET"
cloudflared tunnel --no-autoupdate --url "$TARGET" 2>&1 | while read -r line; do
  echo "$line"
  case "$line" in
    *https://*.trycloudflare.com*)
      if [ ! -f "$OUT" ]; then
        url=$(echo "$line" | tr ' ' '\n' | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | head -1)
        if [ -n "$url" ]; then
          printf '%s' "$url" > "$OUT"
          echo "voucher endpoint published at $url"
        fi
      fi
      ;;
  esac
done
