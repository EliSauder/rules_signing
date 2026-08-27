#!/usr/bin/env bash

# Windows PE signer. Dispatches to signtool or osslsigncode based on --flavor.
# If nothing resolves, copies input -> output unchanged (passthrough).
set -euo pipefail

tool="" infile="" outfile="" digest="sha256"
cert_file="" cert_template="" cert_encoding="path"
password_template="" password_env=""
info_file="" version_file="" stamp_lib="" ts_url="" name="" url=""
declare -a defaults_kv=()

while [ $# -gt 0 ]; do
  case "$1" in
    --tool) tool="$2"; shift 2 ;;
    --in) infile="$2"; shift 2 ;;
    --out) outfile="$2"; shift 2 ;;
    --digest) digest="$2"; shift 2 ;;
    --cert-file) cert_file="$2"; shift 2 ;;
    --cert-template) cert_template="$2"; shift 2 ;;
    --cert-encoding) cert_encoding="$2"; shift 2 ;;
    --password-template) password_template="$2"; shift 2 ;;
    --password-env) password_env="$2"; shift 2 ;;
    --stamp-lib) stamp_lib="$2"; shift 2 ;;
    --stamp-default) defaults_kv+=("$2"); shift 2 ;;
    --info-file) info_file="$2"; shift 2 ;;
    --version-file) version_file="$2"; shift 2 ;;
    --timestamp-url) ts_url="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --url) url="$2"; shift 2 ;;
    *) echo "sign_pe: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# shellcheck source=/dev/null
[ -n "$stamp_lib" ] && source "$stamp_lib"
stamp_load "$info_file" "$version_file"
for kv in "${defaults_kv[@]:-}"; do [ -n "$kv" ] && stamp_default "$kv"; done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

passthrough() {
  echo "sign_pe: $1; passing through unsigned." >&2
  cp "$infile" "$outfile"
  exit 0
}

resolved=""
if [ -n "$cert_file" ]; then
  resolved="$cert_file"
elif [ -n "$cert_template" ]; then
  cert_value="$(stamp_interp "$cert_template")" || passthrough "cert placeholder unresolved"
  [ -z "$cert_value" ] && passthrough "empty cert value"
  if [ "$cert_encoding" = "base64" ]; then
    resolved="$tmp/cert.p12"
    printf '%s' "$cert_value" | base64 -d > "$resolved"
  else
    resolved="$cert_value"
    [ -f "$resolved" ] || passthrough "cert path '$resolved' not found"
  fi
else
  passthrough "no certificate configured"
fi

password=""
if [ -n "$password_template" ]; then
  password="$(stamp_interp "$password_template")" || password=""
elif [ -n "$password_env" ]; then
  password="${!password_env:-}"
fi

args=(sign -pkcs12 "$resolved" -h "$digest")
[ -n "$password" ] && args+=(-pass "$password")
[ -n "$ts_url" ] && args+=(-t "$ts_url")
[ -n "$name" ] && args+=(-n "$name")
[ -n "$url" ] && args+=(-i "$url")
args+=(-in "$infile" -out "$outfile")
"$tool" "${args[@]}"
