#!/usr/bin/env bash
# Apple codesign wrapper. Signs a copy of the input in place.
# If nothing resolves, copies input -> output unchanged (passthrough).
set -euo pipefail

tool="" infile="" outfile=""
cert_file="" cert_template="" cert_encoding="path"
password_template="" password_env="" identity_template=""
info_file="" version_file="" stamp_lib="" options="" entitlements=""
declare -a defaults_kv=()

while [ $# -gt 0 ]; do
  case "$1" in
    --tool) tool="$2"; shift 2 ;;
    --in) infile="$2"; shift 2 ;;
    --out) outfile="$2"; shift 2 ;;
    --cert-file) cert_file="$2"; shift 2 ;;
    --cert-template) cert_template="$2"; shift 2 ;;
    --cert-encoding) cert_encoding="$2"; shift 2 ;;
    --password-template) password_template="$2"; shift 2 ;;
    --password-env) password_env="$2"; shift 2 ;;
    --identity-template) identity_template="$2"; shift 2 ;;
    --stamp-lib) stamp_lib="$2"; shift 2 ;;
    --stamp-default) defaults_kv+=("$2"); shift 2 ;;
    --info-file) info_file="$2"; shift 2 ;;
    --version-file) version_file="$2"; shift 2 ;;
    --options) options="$2"; shift 2 ;;
    --entitlements) entitlements="$2"; shift 2 ;;
    --timestamp-url) shift 2 ;;
    *) echo "sign_apple: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# shellcheck source=/dev/null
[ -n "$stamp_lib" ] && source "$stamp_lib"
stamp_load "$info_file" "$version_file"
for kv in "${defaults_kv[@]:-}"; do [ -n "$kv" ] && stamp_default "$kv"; done

tmp="$(mktemp -d)"
kc=""
cleanup() {
  [ -n "$kc" ] && security delete-keychain "$kc" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT

passthrough() {
  echo "sign_apple: $1; passing through unsigned." >&2
  cp -a "$infile" "$outfile"
  exit 0
}

identity=""
if [ -n "$identity_template" ]; then
  identity="$(stamp_interp "$identity_template")" || identity=""
fi

resolved_cert=""
if [ -n "$cert_file" ]; then
  resolved_cert="$cert_file"
elif [ -n "$cert_template" ]; then
  if cert_value="$(stamp_interp "$cert_template")" && [ -n "$cert_value" ]; then
    if [ "$cert_encoding" = "base64" ]; then
      resolved_cert="$tmp/cert.p12"
      printf '%s' "$cert_value" | base64 -d > "$resolved_cert"
    elif [ -f "$cert_value" ]; then
      resolved_cert="$cert_value"
    fi
  fi
fi

[ -z "$identity" ] && [ -z "$resolved_cert" ] && passthrough "no identity/cert resolved"

password=""
if [ -n "$password_template" ]; then
  password="$(stamp_interp "$password_template")" || password=""
elif [ -n "$password_env" ]; then
  password="${!password_env:-}"
fi

kc_flag=()
if [ -n "$resolved_cert" ]; then
  kc="$tmp/build.keychain"
  security create-keychain -p "" "$kc"
  security unlock-keychain -p "" "$kc"
  security import "$resolved_cert" -k "$kc" -P "$password" -T "$tool"
  security list-keychains -d user -s "$kc" >/dev/null 2>&1 || true
  kc_flag=(--keychain "$kc")
  if [ -z "$identity" ]; then
    identity="$(security find-identity -v -p codesigning "$kc" | awk 'NR==1{print $2}')"
  fi
fi

cp -a "$infile" "$outfile"

args=(--force --sign "$identity" --timestamp)
[ -n "$options" ] && args+=(--options "$options")
[ -n "$entitlements" ] && args+=(--entitlements "$entitlements")
args+=("${kc_flag[@]}" "$outfile")
"$tool" "${args[@]}"
