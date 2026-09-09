#!/usr/bin/env bash
# Build and push the image, so a user needs neither Java, Maven, nor the MidgardJava jar.
#
# Read docs/running.md#distributing-an-image before running this. The image contains MidgardJava,
# which is Tide's and carries no licence, so publishing it redistributes their code. Get their
# permission in writing first. Everything else here is ready.
set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io}"
OWNER="${OWNER:-sashyo}"
NAME="${NAME:-minidauth}"
VERSION="${VERSION:-$(git describe --tags --always)}"
IMAGE="$REGISTRY/$OWNER/$NAME"

if ! ls vendor/MidgardJava*.jar >/dev/null 2>&1; then
  echo "No MidgardJava jar in vendor/. Nothing to build." >&2
  exit 1
fi

# amd64 only, because the jar carries a linux-x86-64 native library and nothing else. Declaring it
# means Apple Silicon gets a clear refusal rather than a crash inside JNA.
docker build --platform linux/amd64 -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

echo
echo "Built $IMAGE:$VERSION"
echo "Push with:"
echo "  docker push $IMAGE:$VERSION && docker push $IMAGE:latest"
