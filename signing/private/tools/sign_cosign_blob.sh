#!/usr/bin/env bash
# Generic blob signer via `cosign sign-blob` (detached bundle).
# If no key resolves, writes an empty bundle marker (passthrough).
set -euo pipefail

tool="" infile="" bundle=""
cert_file="" cert_template="" cert_encoding="path"
password_template="" password_env=""
info_file="" version_file="" stamp_lib=""
declare -a defaults_kv=()

while [ $# -gt 0 ]; do
  case "$1" in
    --tool) tool="$2"; shift 2 ;;
    --in) infile="$2"; shift 2 ;;
    --bundle) bundle="$2"; shift 2 ;;
    --cert-file) cert_file="$2"; shift 2 ;;
    --cert-template) cert_template="$2"; shift 2 ;;
    --cert-encoding) cert_encoding="$2"; shift 2 ;;
    --password-template) password_template="$2"; shift 2 ;;
    --password-env) password_env="$2"; shift 2 ;;
    --stamp-lib) stamp_lib="$2"; shift 2 ;;
    --stamp-default) defaults_kv+=("$2"); shift 2 ;;
    --info-file) info_file="$2"; shift 2 ;;
    --version-file) version_file="$2"; shift 2 ;;
    *) echo "sign_blob: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# shellcheck source=/dev/null
[ -n "$stamp_lib" ] && source "$stamp_lib"
stamp_load "$info_file" "$version_file"
for kv in "${defaults_kv[@]:-}"; do [ -n "$kv" ] && stamp_default "$kv"; done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

passthrough() {
  echo "sign_blob: $1; writing empty passthrough bundle." >&2
  : > "$bundle"
  exit 0
}

key=""
if [ -n "$cert_file" ]; then
  key="$cert_file"
elif [ -n "$cert_template" ]; then
  key_value="$(stamp_interp "$cert_template")" || passthrough "key placeholder unresolved"
  [ -z "$key_value" ] && passthrough "empty key value"
  if [ "$cert_encoding" = "base64" ]; then
    key="$tmp/cosign.key"
    printf '%s' "$key_value" | base64 -d > "$key"
  else
    key="$key_value"
    [ -f "$key" ] || passthrough "key path '$key' not found"
  fi
else
  passthrough "no key configured"
fi

if [ -n "$password_template" ]; then
  if pw="$(stamp_interp "$password_template")"; then export COSIGN_PASSWORD="$pw"; fi
elif [ -n "$password_env" ]; then
  export COSIGN_PASSWORD="${!password_env:-}"
fi

"$tool" sign-blob --yes --key "$key" --bundle "$bundle" "$infile"
