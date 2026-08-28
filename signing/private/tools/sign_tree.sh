#!/usr/bin/env bash
# Signs all files from a source file list and writes them into an output tree.
# Unsupported extensions are copied through unchanged.
set -euo pipefail

out_dir="" tool_mode="auto"
codesign_script="" osslsigncode_script=""
codesign_tool="codesign" osslsigncode_tool="osslsigncode"

cert_file="" cert_template="" cert_encoding="path"
password_template="" password_env="" identity_template=""
info_file="" version_file="" stamp_lib=""
timestamp_url="" name="" url="" options="" entitlements=""

declare -a files=()
declare -a defaults_kv=()

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) out_dir="$2"; shift 2 ;;
    --tool) tool_mode="$2"; shift 2 ;;
    --codesign-script) codesign_script="$2"; shift 2 ;;
    --osslsigncode-script) osslsigncode_script="$2"; shift 2 ;;
    --codesign-tool) codesign_tool="$2"; shift 2 ;;
    --osslsigncode-tool) osslsigncode_tool="$2"; shift 2 ;;
    --file) files+=("$2"); shift 2 ;;
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
    --timestamp-url) timestamp_url="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --url) url="$2"; shift 2 ;;
    --options) options="$2"; shift 2 ;;
    --entitlements) entitlements="$2"; shift 2 ;;
    *) echo "sign_tree: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

[ -n "$out_dir" ] || { echo "sign_tree: missing --out-dir" >&2; exit 2; }
mkdir -p "$out_dir"

detect_tool() {
  local rel="$1"
  case "${rel,,}" in
    *.exe|*.dll|*.sys|*.msi|*.cat|*.ocx|*.efi|*.appx|*.cab|*.ps1|*.ps1xml|*.psc1|*.psd1|*.psm1|*.cdxml|*.mof|*.js)
      echo "osslsigncode"
      ;;
    *.app|*.pkg|*.dmg)
      echo "codesign"
      ;;
    *)
      echo ""
      ;;
  esac
}

declare -a cert_args=()
[ -n "$cert_file" ] && cert_args+=(--cert-file "$cert_file")
[ -n "$cert_template" ] && cert_args+=(--cert-template "$cert_template")
[ -n "$cert_encoding" ] && cert_args+=(--cert-encoding "$cert_encoding")
[ -n "$password_template" ] && cert_args+=(--password-template "$password_template")
[ -n "$password_env" ] && cert_args+=(--password-env "$password_env")
[ -n "$identity_template" ] && cert_args+=(--identity-template "$identity_template")
[ -n "$stamp_lib" ] && cert_args+=(--stamp-lib "$stamp_lib")
[ -n "$info_file" ] && cert_args+=(--info-file "$info_file")
[ -n "$version_file" ] && cert_args+=(--version-file "$version_file")
for kv in "${defaults_kv[@]:-}"; do
  [ -n "$kv" ] && cert_args+=(--stamp-default "$kv")
done

for entry in "${files[@]:-}"; do
  rel="${entry%%=*}"
  src="${entry#*=}"
  dst="$out_dir/$rel"
  mkdir -p "$(dirname "$dst")"

  selected="$tool_mode"
  [ "$selected" = "auto" ] && selected="$(detect_tool "$rel")"

  if [ "$selected" = "osslsigncode" ]; then
    pe_args=(
      --tool "$osslsigncode_tool"
      --in "$src"
      --out "$dst"
      "${cert_args[@]}"
    )
    [ -n "$timestamp_url" ] && pe_args+=(--timestamp-url "$timestamp_url")
    [ -n "$name" ] && pe_args+=(--name "$name")
    [ -n "$url" ] && pe_args+=(--url "$url")
    bash "$osslsigncode_script" "${pe_args[@]}"
  elif [ "$selected" = "codesign" ]; then
    apple_args=(
      --tool "$codesign_tool"
      --in "$src"
      --out "$dst"
      "${cert_args[@]}"
    )
    [ -n "$timestamp_url" ] && apple_args+=(--timestamp-url "$timestamp_url")
    [ -n "$options" ] && apple_args+=(--options "$options")
    [ -n "$entitlements" ] && apple_args+=(--entitlements "$entitlements")
    bash "$codesign_script" "${apple_args[@]}"
  else
    cp -L "$src" "$dst"
  fi
done
