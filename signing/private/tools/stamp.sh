#!/usr/bin/env bash
# Shared stamp interpolation helpers. `source` this from a signer wrapper.
#
# Substitutes {KEY} tokens in a template using values loaded from Bazel's
# workspace status files (stable-status.txt, volatile-status.txt), with an
# optional per-key default map. Literal text around tokens is preserved.
#
# Usage:
#   source stamp.sh
#   stamp_load "$info_file" "$version_file"
#   stamp_default "STABLE_CERT_PATH=/fallback/cert.p12"   # optional, repeatable
#   if value="$(stamp_interp "{STABLE_CERT_PATH}")"; then ...; else passthrough; fi

declare -A _STAMP _STAMP_DEFAULT

stamp_load() {
  local f k v
  for f in "$@"; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    while read -r k v; do
      [ -n "$k" ] || continue
      _STAMP["$k"]="$v"
    done < "$f"
  done
}

stamp_default() {
  local kv="$1" k v
  k="${kv%%=*}"
  v="${kv#*=}"
  [ -n "$k" ] && _STAMP_DEFAULT["$k"]="$v"
}

# stamp_interp TEMPLATE : print the interpolated string on stdout. Returns 1 if
# any {KEY} had neither a stamp value nor a default. Use the RETURN CODE (not a
# variable) since this runs in a "$(...)" subshell:
#   if value="$(stamp_interp "$t")"; then ...; else passthrough; fi
stamp_interp() {
  local rest="$1" out="" key unresolved=0
  while [[ "$rest" == *"{"* ]]; do
    out+="${rest%%\{*}"
    rest="${rest#*\{}"
    if [[ "$rest" != *"}"* ]]; then
      out+="{"
      break
    fi
    key="${rest%%\}*}"
    rest="${rest#*\}}"
    if [ -n "${_STAMP[$key]+x}" ]; then
      out+="${_STAMP[$key]}"
    elif [ -n "${_STAMP_DEFAULT[$key]+x}" ]; then
      out+="${_STAMP_DEFAULT[$key]}"
    else
      unresolved=1
    fi
  done
  out+="$rest"
  printf '%s' "$out"
  return "$unresolved"
}
