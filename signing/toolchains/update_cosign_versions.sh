#!/bin/bash

set -e

RESULTS="$(curl https://api.github.com/repos/sigstore/cosign/releases \
    | jq '.[] | {name: .name, assets: .assets | [ .[] | select(.digest != null) | {name: .name, digest: .digest}]}' \
    | jq -r '.name as $name | .assets.[] | "    \"" + $name + "/" + .name + "\":\"" + .digest + "\","' -r \
    | grep -E "cosign-(linux|darwin|windows)-(amd64|arm64|arm|amd32)" \
    | grep -Ev '\.json|\.pem|\.sig')"

TMPFILE="
COSIGN_HASHES={
${RESULTS}
}
"

echo "$TMPFILE" > cosign_versions.bzl
