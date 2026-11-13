#!/bin/sh
set -eu

# Verify keyless cosign signatures for the deployed image digests. Requires cosign and jq.
# Usage: infra/scripts/verify-images.sh [release-manifest.json]

CERT_IDENTITY="${COSIGN_CERT_IDENTITY:-https://github.com/lexagor/tessera/.github/workflows/images.yml@refs/heads/main}"
CERT_ISSUER="${COSIGN_CERT_ISSUER:-https://token.actions.githubusercontent.com}"
MANIFEST="${1:-}"

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required" >&2
  exit 2
fi

if [ -n "$MANIFEST" ]; then
  images=$(jq -r '.images | to_entries[] | "\(.key)=\(.value)"' "$MANIFEST")
else
  images=$(env | grep '^TESSERA_.*_IMAGE=' | sed 's/^TESSERA_//; s/_IMAGE=/=/')
fi

[ -n "$images" ] || { echo "no image digests found" >&2; exit 2; }
printf '%s\n' "$images" | while IFS='=' read -r name image; do
  [ -n "$image" ] || continue
  echo "verify: $name $image"
  cosign verify \
    --certificate-identity "$CERT_IDENTITY" \
    --certificate-oidc-issuer "$CERT_ISSUER" \
    "$image" >/dev/null
done
echo "image signatures verified"
