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
- Accept either PKCS#12 or PEM credentials. The format is detected from the
  file's contents rather than its name, so base64-encoded and stamped
  certificates work regardless of how they are named on disk.
- Use a single certificate across all three signers. PKCS#12 is converted to
  PEM and imported into cosign's key format during the build (see
  [Signing with a single certificate](#signing-with-a-single-certificate)).
- Embed an issuing chain in the signature with `ca_file`, so verifiers can build
  a trust path back to the root without fetching intermediates themselves.
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

### Stamping

`{KEY}` placeholders in `certificate`/`password`/`identity` are resolved
against Bazel's workspace status (`--stamp` and `--workspace_status_command`),
using the same convention as the rest of the Bazel ecosystem: `sign` accepts
the standard `stamp` attribute from
[`@bazel_lib//lib:stamping.bzl`](https://github.com/bazel-contrib/bazel-lib/blob/main/lib/stamping.bzl)
(`STAMP_ATTRS`, `maybe_stamp`).

- `stamp = -1` (the default) follows the build-wide `--stamp`/`--nostamp` flag.
- `stamp = 1` always stamps this target, even with `--nostamp`.
- `stamp = 0` never stamps this target, even with `--stamp`.

Stamping is only consulted when a template actually contains a `{KEY}`
placeholder, and real values are only read from the workspace status files
when stamping is enabled for the build/target; otherwise unresolved keys fall
back to `stamp_defaults`. This keeps a plain `bazel build` reproducible and
free of the volatile-status dependency unless you explicitly opt in:

```starlark
sign(
    name = "signed_bundle",
    src = ":artifact_bundle",
    certificate = ":release_cert",
    stamp = 1,  # or rely on --stamp / --nostamp
)
```

### Transparency log

`cosign sign-blob` publishes the artifact digest to the public Rekor
transparency log unless told otherwise, which would make every signing action a
network call and record a hash of your build output in a public ledger.
`rules_signing` therefore does not publish anything by default — you opt in by
naming the log to publish to:

```starlark
sign(
    name = "signed_bundle",
    src = ":artifact_bundle",
    certificate = ":release_cert",

    # "default"                        the public Sigstore instance
    # "https://rekor.internal.example" a specific (e.g. private) instance
    # ""                               the default: publish nothing
    transparency_log = "default",
)
```

Leaving it unset keeps signing entirely local, in which case there is no log
entry to check and verification needs `--insecure-ignore-tlog`:

```bash
cosign verify-blob --key cert-public-key.pem --bundle artifact.bundle.json \
    --insecure-ignore-tlog artifact
```

### Timestamping

A trusted timestamp records *when* a signature was made, so that it keeps
validating after the signing certificate expires. Obtaining one means contacting
a timestamp authority during the build, so — like the transparency log — it is
opt-in:

```starlark
sign(
    name = "signed_installer",
    src = ":installer",
    certificate = ":release_cert",

    # "default"                     the well-known authority for the signer in use
    # "http://tsa.example/ts"       a specific (e.g. internal) authority
    # ""                            the default: do not timestamp
    timestamp_url = "default",
)
```

`"default"` resolves per signer: `http://timestamp.apple.com/ts01` for
`rcodesign` and `http://timestamp.digicert.com` for `osslsigncode`.

Note that `rcodesign` timestamps against Apple's authority unless it is actively
told not to, so leaving `timestamp_url` unset makes `rules_signing` pass
`--timestamp-url none` explicitly rather than omitting the flag.

The trade-off for the default is that an untimestamped signature is only
verifiable while the certificate is valid; releases you expect to outlive the
certificate should set this.

### Signing with a single certificate

A `sign` target carries exactly one certificate, but `tool = "auto"` may dispatch
to three different signers. One certificate can drive all three, provided it is
issued as a plain code-signing certificate:

- **PEM, not PKCS#12** — the private key and the certificate in one file, key
  first. `osslsigncode` takes it as both `-certs` and `-key`, and `rcodesign`
  takes it as `--pem-file`.
- **No Apple-specific critical extensions** — `rcodesign generate-self-signed-certificate`
  emits an Apple profile whose critical extensions `osslsigncode` refuses. An
  `extendedKeyUsage` of `codeSigning` is all that is needed.
- **RSA-2048 or EC P-256** — both are accepted by every signer.

`cosign` uses bare-key trust and ignores X.509 entirely, so it cannot consume a
certificate directly. `sign` bridges this by running `cosign import-key-pair` on
the certificate's private key during the action, which yields a cosign keypair
holding the *same* key the certificate carries. Signatures therefore verify
against the certificate's public key:

```bash
cosign verify-blob --key cert-public-key.pem --bundle artifact.bundle.json artifact
```

A PKCS#12 certificate is converted to PEM automatically, but only if the
optional openssl toolchain is registered:

```starlark
signing_tools = use_extension("@rules_signing//signing:extensions.bzl", "signing_tools")
signing_tools.openssl(path = "openssl")
use_repo(signing_tools, "signing_openssl")

register_toolchains("@signing_openssl//:openssl_toolchain")
```

The toolchain is opt-in because the BCR `openssl` module builds from source, and
most builds never need the conversion. Without it, a PKCS#12 certificate routed
to `cosign` fails with an actionable message rather than a cryptic cosign error.

Production Apple distribution still requires a real Apple-issued Developer ID
certificate, which no other signer will accept — the single-certificate path is
for development and internal signing.

### Issuing chains

Verifiers need every certificate between the leaf and the trust anchor. The leaf
is always embedded in the signature, but intermediates are not. Point `ca_file`
at the intermediates so they travel with the signature:

```starlark
certificate(
    name = "release_cert",
    certificate_file = "leaf-and-key.pem",
    ca_file = "intermediates.pem",
)
```

`osslsigncode` embeds them via `-ac` and `rcodesign` adds them as extra
certificates in the CMS structure. `cosign` ignores `ca_file`, since bare-key
trust has no chain to build.

## Standalone consumer module test

A real consumer-module workspace lives at `usagetest/` with its own `MODULE.bazel`.

```bash
cd usagetest
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs
```
