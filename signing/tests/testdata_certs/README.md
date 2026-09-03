# Development signing certificates

Throwaway, self-signed signing material used by the test suite. It is checked
in so tests can produce and verify **real** signatures without needing network
access, a host `openssl`, or per-run key generation.

> **These are not secrets.** The private keys and the password
> (`rules-signing-dev`) are public by design. Nothing outside this repository's
> test fixtures is ever signed with them, and the certificates are self-signed,
> so no client will trust them. Never use them for anything real.

## Contents

| File | Used by | Purpose |
| --- | --- | --- |
| `generic.pem` | osslsigncode | Unified PEM: private key followed by certificate |
| `generic.crt` | osslsigncode | Certificate only; the trust anchor for `verify -CAfile` |
| `generic.p12` | osslsigncode | Same key/certificate as PKCS#12, password protected |
| `apple.pem` | codesign (rcodesign) | Unified PEM in Apple's code-signing profile |
| `apple.crt` | codesign (rcodesign) | Certificate only |
| `apple.p12` | codesign (rcodesign) | Same key/certificate as PKCS#12, password protected |
| `cosign.key` | cosign | Encrypted Sigstore private key |
| `cosign.pub` | cosign | Public key used to verify detached signatures |
| `shared_root.crt` | all three | Root CA; the only trust anchor verifiers are given |
| `shared_ca.crt` | all three | Intermediate CA; what `ca_file` points at |
| `shared.pem` | all three | Unified PEM leaf: private key followed by certificate |
| `shared.crt` | all three | Leaf certificate only |
| `shared.pub` | cosign | Leaf's public key, for `cosign verify-blob --key` |
| `shared.p12` | all three | Same leaf as PKCS#12, exercising the openssl conversion |
| `certs.bzl` | BUILD files | Password, plus base64 PKCS#12 for the string-encoded certificate mode |

## Why the per-tool certificates still exist

`shared.*` proves one certificate can drive all three signers, but the per-tool
sets are kept because they cover material real users will bring:

- rcodesign's Apple-profile certificate carries X.509 extensions that
  osslsigncode rejects with `unhandled critical extension`, which is why an
  Apple Developer ID certificate cannot be the shared one.
- cosign refuses ordinary PEM private keys (`unsupported pem type: PRIVATE
  KEY`); it only reads its own password-encrypted Sigstore key format. A
  pre-existing `cosign.key` must keep working without conversion.

## Why the shared certificate is a three-level chain

The leaf is always embedded in a signature, so a root-signed leaf would verify
whether or not `ca_file` did anything. Interposing an intermediate makes the
test meaningful: verification is given only `shared_root.crt`, so it can only
succeed if `ca_file` embedded the intermediate in the signature.

## Regenerating

```console
$ bazel run //signing/tests/testdata_certs:regenerate
```

The certificates are valid for 20 years. The expiry cannot be pushed past 2049:
X.509 `UTCTime` stores a two-digit year and rcodesign uses it unconditionally,
so a longer validity silently wraps into the past. `regenerate` fails loudly if
that happens.

Regenerating rewrites `certs.bzl` as well, since it embeds the base64 form of
`generic.p12` and `shared.p12`.
