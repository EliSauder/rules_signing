# rules_signing

`rules_signing` wraps outputs from another Bazel target, signs supported artifacts, and returns the same relative file structure with signed outputs.

## What works now

- Wrap any target that exposes `DefaultInfo.files`.
- Preserve source output layout (relative paths) in a single output tree artifact.
- Auto-select signer by file extension:
  - `osslsigncode`: `.exe`, `.dll`, `.msi`, `.sys`, and related Windows script/package extensions.
  - `codesign`: `.app`, `.pkg`, `.dmg`.
- Copy unsupported extensions through unchanged.
- Support cert/key material from:
  - direct file (`certificate_file`)
  - stamped template (`certificate`) using `{KEY}` placeholders.
- For Apple artifacts, `identity` is optional when the resolved certificate contains a codesigning identity.

## Basic usage

```starlark
load("//signing:defs.bzl", "sign", "certificate")

certificate(
    name = "release_cert",
    certificate = "{STABLE_CERT_PATH}",
    certificate_encoding = "path",
    password = "{STABLE_CERT_PASSWORD}",
    stamp_defaults = {
        "STABLE_CERT_PATH": "/tmp/dev-cert.p12",
    },
)

sign(
    name = "signed_bundle",
    src = ":artifact_bundle",
    certificate = ":release_cert",
    tool = "auto",  # auto | osslsigncode | codesign
)
```

The `sign` target emits a **directory artifact** containing the signed/copied files under the same relative paths as the wrapped target.

## Standalone consumer module test

A real consumer-module workspace lives at `usagetest/` with its own `MODULE.bazel`.

```bash
cd usagetest
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs
```
