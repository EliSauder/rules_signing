# rules_signing

`rules_signing` wraps outputs from another Bazel target, signs supported artifacts, and returns the same relative file structure with signed outputs.

## What works now

- Wrap any target that exposes `DefaultInfo.files`.
- Preserve source output layout (relative paths) in a single output tree artifact.
- Auto-select signer by file extension, then by file contents:
  - `osslsigncode`: `.exe`, `.dll`, `.msi`, `.sys`, and related Windows script/package extensions.
  - `codesign`: `.app`, `.pkg`, `.dmg`.
  - `cosign sign-blob`: all other file types, producing colocated `.sig` and `.bundle.json` files.
- Detect extensionless executables by parsing their headers with
  [LIEF](https://lief.re/), so a Mach-O binary (which normally has no extension
  on macOS) or an extensionless PE still reaches its native signer instead of
  falling back to a detached signature. An explicit extension always wins.
- Sign `rules_oci` `oci_image` outputs as OCI layouts (no registry push during build).
- Preserve the original file alongside any detached signature outputs.
- Preserve upstream runfiles on wrapped targets (including `oci_image` runfiles).
- Support cert/key material from:
  - direct file (`certificate_file`)
  - stamped template (`certificate`) using `{KEY}` placeholders.
- For Apple artifacts, signing is hermetic and cross-platform: the `codesign.bzl`
  toolchain ships `rcodesign` prebuilts, so `.app`/`.pkg`/`.dmg` and Mach-O
  binaries are signed from Linux and Windows workers too, with no keychain and
  no dependency on Apple's `/usr/bin/codesign`. `identity` is optional and maps
  to the signature's binary identifier. Register the toolchain with
  `register_toolchains("@codesign.bzl//toolchain:all")` (see [Setup](#setup)).

## Setup

`rules_signing` ships toolchain *types* and toolchain *rules*, but deliberately
registers no signing toolchains of its own. That keeps tool choice, tool
versions, and platform coverage in your hands, and keeps this module's own test
dependencies out of your build graph. Declare the tool repositories you want and
register them yourself:

```starlark
bazel_dep(name = "rules_signing", version = "<version>")

signing_tools = use_extension("@rules_signing//signing:extensions.bzl", "signing_tools")
use_repo(
    signing_tools,
    "signing_cosign",
    "signing_osslsigncode",
)

register_toolchains(
    "@signing_cosign//:cosign_toolchain",
    "@signing_osslsigncode//:osslsigncode_toolchain",
)

# Only needed if you sign Apple artifacts or Mach-O binaries.
bazel_dep(name = "codesign.bzl", version = "<version>")

register_toolchains("@codesign.bzl//toolchain:all")
```

Only register the toolchains you actually need. `sign` resolves toolchains
lazily and fails with an actionable message naming the missing registration if
an input requires a signer you have not registered.

You may also skip the `signing_tools` extension entirely and point the
`cosign_toolchain` / `osslsigncode_toolchain` rules from
`@rules_signing//signing/toolchains:toolchains.bzl` at binaries you supply.

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
    tool = "auto",  # auto | osslsigncode | codesign | cosign
)
```

The `sign` target emits a **directory artifact** containing the signed/copied files under the same relative paths as the wrapped target.

For `oci_image` sources, `sign` copies the OCI layout output, signs the root manifest blob with `cosign sign-blob` (when a key resolves), and writes the signature bundle under `signatures/` in the output layout. Other directory artifacts retain their complete directory structure and are traversed recursively, signing individual files selected by extension (for example, `.exe` and `.dll`). Files without a native signer receive colocated cosign `.sig` and `.bundle.json` outputs.

## Standalone consumer module test

A real consumer-module workspace lives at `usagetest/` with its own `MODULE.bazel`.

```bash
cd usagetest
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs
```
