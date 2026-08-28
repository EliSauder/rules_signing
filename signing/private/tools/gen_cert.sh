#!/usr/bin/env bash
# Generate a self-signed PKCS#12 (dev/test use only) with openssl.
set -euo pipefail

openssl_bin="openssl"
out=""
subject="/CN=rules_signing dev"
days="825"
password=""

while [ $# -gt 0 ]; do
  case "$1" in
    --openssl) openssl_bin="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --subject) subject="$2"; shift 2 ;;
    --days) days="$2"; shift 2 ;;
    --password) password="$2"; shift 2 ;;
    *) echo "gen_cert: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

[ -n "$out" ] || { echo "gen_cert: --out is required" >&2; exit 2; }
case "$subject" in /*) : ;; *) subject="/$subject" ;; esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

"$openssl_bin" req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" \
  -days "$days" -subj "$subject" \
  -addext "keyUsage=digitalSignature" \
  -addext "extendedKeyUsage=codeSigning"

"$openssl_bin" pkcs12 -export \
  -inkey "$tmp/key.pem" -in "$tmp/cert.pem" \
  -passout "pass:$password" -out "$out"
