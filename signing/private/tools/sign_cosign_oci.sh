#!/usr/bin/env bash
# OCI signing helper placeholder. Current implementation preserves passthrough
# behavior by writing an empty signature output when no concrete OCI workflow is
# configured by the caller.
set -euo pipefail

out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done

[ -n "$out" ] || exit 0
mkdir -p "$(dirname "$out")"
: > "$out"