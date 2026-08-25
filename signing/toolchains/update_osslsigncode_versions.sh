#!/bin/bash

set -e

RESULTS="$(curl https://api.github.com/repos/EliSauder/osslsigncode/releases \
    | jq '.[] | {name: .name, assets: .assets | [ .[] | select(.digest != null) | {name: .name, digest: .digest}]}' \
    | jq -r '.name as $name  | .assets.[] | "    \"" + $name + "/" + .name + "\":\"" + .digest + "\","' -r \
    | grep -E "osslsigncode(-[0-9\.]+)-(linux|darwin|windows)-(amd64|arm64|arm|amd32)" \
    | grep -Ev '\.json|\.pem|\.sig')"

TMPFILE="
OSSLSIGNCODE_HASHES={
${RESULTS}
}
"

echo "$TMPFILE" > osslsigncode_versions.bzl
