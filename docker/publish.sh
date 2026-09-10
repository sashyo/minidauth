#!/usr/bin/env bash
# Build and push the image, so a user needs neither Java, Maven, nor the MidgardJava jar.
#
# The image carries Tide's MidgardJava jar, compiled and unmodified, which Tide permits. It never
# carries Midgard's source, and neither does this repository: the jar is supplied in vendor/, which
# git ignores, and only the built image leaves this machine.
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io}"
OWNER="${OWNER:-sashyo}"
REPO="${REPO:-minidauth}"
VERSION="${VERSION:-$(git describe --tags --always)}"
IMAGE="$REGISTRY/$OWNER/$REPO"

if ! ls vendor/MidgardJava*.jar >/dev/null 2>&1; then
  echo "No MidgardJava jar in vendor/. Nothing to build." >&2
  exit 1
fi

# amd64 only, because the jar carries a linux-x86-64 native library and nothing else. Declaring it
# means Apple Silicon runs it under emulation rather than failing inside JNA.
docker build --platform linux/amd64 -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

# The tunnel is published alongside, so docker-compose.yml works when downloaded on its own.
docker build --platform linux/amd64 -f docker/Dockerfile.tunnel \
  -t "$IMAGE-tunnel:$VERSION" -t "$IMAGE-tunnel:latest" .

if [ "${PUSH:-}" = "1" ]; then
  for tag in "$VERSION" latest; do
    docker push "$IMAGE:$tag"
    docker push "$IMAGE-tunnel:$tag"
  done
  echo "Pushed $IMAGE and $IMAGE-tunnel at $VERSION"
else
  echo
  echo "Built $IMAGE:$VERSION and $IMAGE-tunnel:$VERSION"
  echo "Push with: PUSH=1 VERSION=$VERSION docker/publish.sh"
fi
