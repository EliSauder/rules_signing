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
  - direct file (`certificate_file`, a `.p12`/`.pfx`/`.pem`/`.key` label)
  - stamped template (`certificate`) using `{KEY}` placeholders.
  - a certificate generated during the build by `self_signed_certificate` (see
    [Generating a self-signed certificate](#generating-a-self-signed-certificate)).
- Accept either PKCS#12 or PEM credentials. The format is detected from the
  file's contents rather than its name, so base64-encoded and stamped
  certificates work regardless of how they are named on disk. (A direct
  `certificate_file` label must still carry a `.p12`, `.pfx`, `.pem` or `.key`
  extension, which is Bazel's own input filter rather than a format decision.)
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

# Needed if you sign Apple artifacts or Mach-O binaries, and also for any
# directory artifact signed with `tool = "auto"` (see below).
bazel_dep(name = "codesign.bzl", version = "<version>")

register_toolchains("@codesign.bzl//toolchain:all")
```

Only register the toolchains you actually need. `sign` resolves toolchains
lazily and fails with an actionable message naming the missing registration if
an input requires a signer you have not registered.

**Directory artifacts require every signer to be registered.** Which signer an
individual file needs is decided from its extension or its header bytes, and
the contents of a directory artifact (an `oci_image` layout, a `.app` bundle,
or any other tree artifact) do not exist yet at analysis time. `tool = "auto"`
therefore has to assume a tree may hold anything — nested `.exe`/`.dll` files
needing `osslsigncode`, or Mach-O binaries and `.app`/`.dmg`/`.pkg` bundles
needing `codesign` — and requires **all** signing toolchains, including
`codesign.bzl`, even when nothing in the tree turns out to be an Apple
artifact. The same applies to extensionless files, which are classified by
sniffing their headers while the action runs.

If you do not want to register signers you will never use, name the one you
need explicitly and no other toolchain is requested:

```starlark
sign(
    name = "signed_image",
    src = ":my_oci_image",
    certificate = ":release_cert",
    tool = "cosign",  # skips the osslsigncode/codesign toolchain requirement
)
```

You may also skip the `signing_tools` extension entirely and point the
`cosign_toolchain` / `osslsigncode_toolchain` rules from
`@rules_signing//signing/toolchains:toolchains.bzl` at binaries you supply.

## Basic usage

```starlark
load("@rules_signing//signing:defs.bzl", "sign", "certificate")

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

For `oci_image` sources, `sign` copies the OCI layout output, signs the root manifest blob with `cosign sign-blob` (when a key resolves), and writes the signature bundle under `signatures/` in the output layout. Other directory artifacts retain their complete directory structure and are traversed recursively, signing individual files selected by extension (for example, `.exe` and `.dll`). Files without a native signer receive colocated cosign `.sig` and `.bundle.json` outputs. Note that with `tool = "auto"` any directory artifact requires every signing toolchain to be registered — see [Setup](#setup).

### Stamping

`{KEY}` placeholders in `certificate`/`password`/`identity` are resolved
against Bazel's workspace status (`--stamp` and `--workspace_status_command`),
using the same convention as the rest of the Bazel ecosystem: both
`certificate` and `sign` accept the standard `stamp` attribute from
[`@bazel_lib//lib:stamping.bzl`](https://github.com/bazel-contrib/bazel-lib/blob/main/lib/stamping.bzl)
(`STAMP_ATTRS`, `maybe_stamp`), each evaluating its own independently:

- `stamp = -1` (the default) follows the build-wide `--stamp`/`--nostamp` flag.
- `stamp = 1` always stamps this target, even with `--nostamp`.
- `stamp = 0` never stamps this target, even with `--stamp`.

`certificate` resolves its own `certificate` template (if any) into a real,
already-decoded certificate file exactly once, using its own `stamp`
attribute — not the consuming `sign` target's. This matters because one
`certificate` can back several `sign` targets: stamping is decided where the
secret is materialized, so every consumer sees the same resolved bytes
instead of each `sign` action re-interpolating (and separately deciding
whether to stamp) the same template. `password`/`identity` remain plain
string templates, resolved by the consuming `sign` target's own `stamp`
setting when the signing action runs, since turning a password into a cached
build output would be a worse practice than passing it as an argument.

A `path`-encoded `certificate` template that renders to a location which does
not exist on disk (e.g. a secret not present in this build environment) is
tolerated rather than treated as a hard error — the affected `sign` targets
just proceed as if no certificate had been configured. An unresolved `{KEY}`
placeholder (no `stamp_defaults` entry and stamping disabled or missing the
key) is always a hard build error, since that usually means a workspace
status key was never wired up.

Stamping is only consulted when a template actually contains a `{KEY}`
placeholder, and real values are only read from the workspace status files
when stamping is enabled for the build/target; otherwise unresolved keys fall
back to `stamp_defaults`. This keeps a plain `bazel build` reproducible and
free of the volatile-status dependency unless you explicitly opt in:

```starlark
certificate(
    name = "release_cert",
    certificate = "{STABLE_CERT_PATH}",
    certificate_encoding = "path",
    stamp = 1,  # or rely on --stamp / --nostamp
    stamp_defaults = {
        "STABLE_CERT_PATH": "/tmp/dev-cert.p12",
    },
)

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

The toolchain is opt-in because most builds never need the conversion. The
repository rule adopts an `openssl` already present on the host — `path`
accepts either a literal path or a bare program name resolved against `PATH`,
which is why the same tag works on Linux, macOS and Windows. Use
`signing_tools.openssl(label = ...)` instead to point at an `openssl` built by
another module. Without the toolchain, a PKCS#12 certificate routed to
`cosign` fails with an actionable message rather than a cryptic cosign error.

Production Apple distribution still requires a real Apple-issued Developer ID
certificate, which no other signer will accept — the single-certificate path is
for development and internal signing.

### Generating a self-signed certificate

Not every build has a key to sign with. Contributors, CI branches and local
development builds usually have none, and checking a private key into the
repository to fill the gap makes the credential public and permanent.
`self_signed_certificate` issues one during the build instead, and provides it
wherever a `certificate` target is accepted:

```starlark
load("@rules_signing//signing:defs.bzl", "self_signed_certificate", "sign")

self_signed_certificate(
    name = "dev_cert",
    common_name = "Example development (DO NOT TRUST)",
    organization = "Example",
    validity_days = 365,
)

sign(
    name = "signed_bundle",
    src = ":artifact_bundle",
    certificate = ":dev_cert",
)
```

The rule requires the [openssl toolchain](#signing-with-a-single-certificate)
and produces three files:

| File | Contents |
| --- | --- |
| `<name>.pem` (or `<name>.p12`) | The signing material: private key plus certificate. This is what `SigningCertificateInfo` points at. |
| `<name>.crt` | The certificate alone — the trust anchor to verify against, e.g. `osslsigncode verify -CAfile <name>.crt`. |
| `<name>.pub` | The certificate's public key, for `cosign verify-blob --key`. |

Each is also exposed as an output group (`certificate`, `certificate_only` and
`public_key`) so a single file can be extracted with a `filegroup`:

```starlark
filegroup(
    name = "dev_cert_anchor",
    srcs = [":dev_cert"],
    output_group = "certificate_only",
)
```

By default the rule emits an RSA-2048 key and a unified PEM, which every signer
reads directly; `format = "p12"` wraps it in a PKCS#12 bundle protected by
`password` instead, and `key_type = "ec"` selects an EC key (`ec_curve`,
default P-256). The certificate carries a `digitalSignature` key usage and a
`codeSigning` extended key usage and nothing else, which is exactly the profile
[all three signers accept](#signing-with-a-single-certificate). Subject fields
(`organizational_unit`, `country`, `state`, `locality`, `email`,
`subject_alt_names`) and `{KEY}` stamping of `common_name`, `organization` and
`password` work the same way as on `certificate`.

Two things follow from the certificate being generated rather than supplied:

- **Nothing trusts it.** It is its own issuer, so verification only succeeds
  against the generated `<name>.crt`/`<name>.pub`. Use it for development,
  tests and internal artifacts; releases still need a real certificate.
- **The key is regenerated whenever the action reruns**, which invalidates
  signatures made with the previous one. The action is marked as not remotely
  cacheable so a freshly generated private key is never uploaded to a cache
  other people can read; the local cache still keeps it stable across builds.
  Pin it with `certificate(certificate_file = ...)` if you need a credential
  that outlives your output tree.

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

## Calling the signer from your own rule

`sign` covers "take these files, give me signed copies". A rule that *produces*
a signable artifact often needs something different: the thing to sign does not
exist at analysis time, and sometimes cannot be signed by a separate action at
all. NSIS is the standard example. Its uninstaller only exists during the
`makensis` run, and is signed through the `!uninstfinalize` hook, which hands a
signer a path and expects the file at that path to come back signed. There is no
intermediate artifact to feed to a `sign` target.

`//signing:actions.bzl` exposes the pieces `sign` is built from so a rule can do
this itself, without reimplementing certificate handling, toolchain resolution
or the accompanying diagnostics.

```starlark
load(
    "@rules_signing//signing:actions.bzl",
    "SIGNING_ATTRS",
    "SIGNING_TOOLCHAINS",
    "signing_argv",
    "signing_context",
)

def _installer_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".exe")

    # Nothing to inspect at analysis time, so name the signer this rule always
    # needs. A missing toolchain then fails during analysis with an actionable
    # message instead of part-way through the action.
    sctx = signing_context(
        ctx,
        require = ["osslsigncode"],
        require_reason = "an NSIS uninstaller is always a PE executable",
    )

    # Omitting `outfile` signs in place, which is what a finalize hook wants.
    # "%1" is NSIS' placeholder for the file it just produced.
    command = signing_argv(sctx, infile = "%1")

    ctx.actions.run(
        executable = ctx.executable._makensis,
        arguments = [...],  # pass `command` through to !finalize/!uninstfinalize
        inputs = depset([...], transitive = [sctx.inputs]),
        tools = sctx.tools,
        outputs = [out],
        env = sctx.env,
    )

installer = rule(
    implementation = _installer_impl,
    attrs = dict({...}, **SIGNING_ATTRS),
    toolchains = SIGNING_TOOLCHAINS,
)
```

`SIGNING_ATTRS` contributes the signing options under a `signing_` prefix —
`signing_certificate`, `signing_tool`, `signing_timestamp_url` and the rest —
so your rule gains `sign`'s whole surface without declaring it, and without the
generic names (`tool`, `url`, `description`, `options`) colliding with
attributes your rule already defines:

```starlark
installer(
    name = "my_installer",
    tool = "my-own-packager",          # your rule's attribute
    signing_tool = "osslsigncode",     # rules_signing's
    signing_certificate = ":release_cert",
)
```

If you would rather use the bare names, call `signing_attrs(prefix = "")` and
pass the matching `attr_prefix = ""` to `signing_context`. Any other prefix
works the same way, as long as the two agree. (`stamp` is contributed
unprefixed either way, since `maybe_stamp` looks it up by that exact name.)

`signing_context` returns the resolved signer plus the `inputs`, `tools` and
`env` your action must declare.

Everything that is not an input or output path — including certificate paths and
passwords — goes into a parameter file that `signing_argv` references as
`--args-file=<path>`. That keeps credentials out of process listings and out of
any script your rule generates, and avoids the embedding tool's quoting rules
entirely. The resulting command is just two fixed tokens plus the path being
signed.

Note the flag is deliberately *not* the customary `@<path>` spelling. The
Cygwin/MSYS2 runtime behind Git for Windows' `bash` expands `@file` arguments
itself, splitting the file on whitespace rather than on lines, which tears any
argument containing a space into several. Since the point of the parameter file
is to survive being handed through an intermediary process, it uses a flag no
intermediary claims.

`signing_argv` also builds commands that sign to a separate output (pass
`outfile`), or that sign many files in one pass (`rel_src_manifest` with
`out_dir`). Use `path_fn` when the consuming tool needs a different path
spelling, such as Windows-style separators. For the plain "sign these files,
keep their layout" case, call `sign_action` and skip building the command line.

## Standalone consumer module test

A real consumer-module workspace lives at `usagetest/` with its own `MODULE.bazel`.

```bash
cd usagetest
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs //:signed_oci_image
```
