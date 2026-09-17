# rules_signing

`rules_signing` wraps outputs from another Bazel target, signs supported artifacts, and returns the same relative file structure with signed outputs.

## What works now

- Wrap any target that exposes `DefaultInfo.files`.
- Preserve source output layout (relative paths), with one output artifact per
  source: a file is signed into a file, a directory into a directory. Only a
  detached signature adds files, and only the ones it consists of.
- Auto-select signer from the file's extension, or from the rule that produces it:
  - `osslsigncode`: `.exe`, `.dll`, `.msi`, `.sys`, and related Windows script/package extensions.
  - `codesign`: `.app`, `.pkg`, `.dmg`.
  - `jarsigner`: `.jar`, including the jar a `java_binary`/`java_library`,
    `kt_jvm_binary`/`kt_jvm_library` or `scala_binary`/`scala_library` builds
    beside its launcher script.
  - `cosign sign-blob`: all other file types, producing colocated `.sig` and `.bundle.json` files.
- Recognise extensionless native binaries without reading them, by asking which
  rule builds the file and which platform it is built for — so a `cc_binary`
  cross-compiled to Windows reaches `osslsigncode` even though it is called
  `hello`. See [How a signer is chosen](#how-a-signer-is-chosen).
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
  to the signature's binary identifier. Register both the upstream toolchains
  and the opt-in adapter (see [Apple signing toolchain](#apple-signing-toolchain)).
- For jars, an optional jarsigner toolchain adapts a Bazel/rules_java JDK.
  Register it explicitly when signing jars; other consumers do not need Java.
  Both local and remotely supplied JDKs are supported (see [JDK selection](#jdk-selection)).
  The signing material is
  repackaged into a throwaway PKCS#12 keystore during the build (see
  [Signing with a single certificate](#signing-with-a-single-certificate)),
  so a PEM certificate works here too even though jarsigner itself only reads
  a keystore.

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

register_toolchains(
    "@codesign.bzl//toolchain:all",
    "@rules_signing//signing/toolchains:codesign_toolchain",
)

# Needed only for jars or directory artifacts signed with tool = "auto".
# Uses Bazel's local JDK discovery (JAVA_HOME/PATH); requires a full JDK.
register_toolchains("@rules_signing//signing/toolchains:local_jarsigner_toolchain")
```

Only register the toolchains you actually need. An unregistered toolchain is
allowed until an input requires its signer, at which point `sign` reports an
actionable error naming the missing registration. This is not lazy resolution:
Bazel analyzes any selected registered implementation before `sign` runs.
A broken registered JDK can therefore still fail analysis for non-JAR inputs;
leave jarsigner unregistered in consumers that do not need it.

### Apple signing toolchain

Apple signing uses `@rules_signing//signing/toolchains:codesign_toolchain_type`,
separate from `codesign.bzl`'s upstream type. The default adapter,
`@rules_signing//signing/toolchains:codesign_toolchain`, delegates executable
selection to the registered `@codesign.bzl//toolchain:all` toolchains. It uses
the **execution platform** even when building artifacts for another platform.
No tool discovery or prebuilt-download logic is duplicated here.

Registering the upstream toolchains alone no longer enables Apple signing:
existing consumers must also register the adapter shown in [Setup](#setup).
Without that registration, other signing targets do not resolve the upstream
codesign toolchain, and Apple inputs report a missing codesign registration.
The `codesign.bzl` module remains a dependency to provide the default adapter;
its signer executable is not needed unless that adapter is selected.

To supply your own rcodesign executable instead, define and register a custom
implementation. This bypasses upstream toolchain resolution:

```starlark
load("@rules_signing//signing/toolchains:toolchains.bzl", "codesign_toolchain")

codesign_toolchain(
    name = "my_codesign",
    codesign = "//tools:rcodesign",
    # Optional shared libraries or other runtime files:
    data = ["//tools:rcodesign_runtime_files"],
)

toolchain(
    name = "my_codesign_toolchain",
    toolchain = ":my_codesign",
    toolchain_type = "@rules_signing//signing/toolchains:codesign_toolchain_type",
    exec_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
)
```

The executable's runfiles and `data` are included in signing actions.
**Apple's `/usr/bin/codesign` is not a drop-in replacement:** this signer uses
the rcodesign CLI, which is different from Apple's native tool.

### JDK selection

There are two ready-made implementations; register **one**:

| Registration under `@rules_signing//signing/toolchains:` | JDK source |
| --- | --- |
| `local_jarsigner_toolchain` | Bazel's `@bazel_tools//tools/jdk:jdk`, using its standard local JDK discovery. |
| `jarsigner_toolchain` | Bazel's `@bazel_tools//tools/jdk:current_java_runtime` in the execution configuration, using the registered Java runtime toolchains. |

For a downloaded JDK, use the second implementation:

```starlark
register_toolchains("@rules_signing//signing/toolchains:jarsigner_toolchain")
```

Select its runtime with `--tool_java_runtime_version=remotejdk_17` (or another
version supported by your `rules_java`). `--tool_java_runtime_version=local_jdk`
selects the local JDK through the same adapter. The `--java_runtime_version`
flag alone does not select the signing JDK: jarsigner runs on the **execution**
platform, not the platform of the artifact being signed.

To use a particular downloaded or custom `java_runtime` target, define an
adapter in your BUILD file and register its `toolchain` target:

```starlark
load("@rules_signing//signing/toolchains:toolchains.bzl", "jarsigner_toolchain")

jarsigner_toolchain(
    name = "my_jarsigner",
    java_runtime = "@my_jdk//:jdk",
)

toolchain(
    name = "my_jarsigner_toolchain",
    toolchain = ":my_jarsigner",
    toolchain_type = "@rules_signing//signing/toolchains:jarsigner_toolchain_type",
    exec_compatible_with = ["@platforms//os:linux", "@platforms//cpu:x86_64"],
)
```

The runtime must expose the standard `ToolchainInfo.java_runtime` provider and
contain `jarsigner` or `jarsigner.exe`. The adapter carries the whole JDK into
the signing action, including shared libraries and `keytool`. It reuses Bazel
and `rules_java` resolution rather than probing the host or downloading Java
itself. Existing consumers that relied on implicit Java runtime registration
must now explicitly register a jarsigner implementation.

**Directory artifacts require every signer to be registered.** Which signer an
individual file needs is decided while the build graph is built, and the
contents of a directory artifact (an `oci_image` layout, a `.app` bundle, or
any other tree artifact) do not exist yet at that point. `tool = "auto"`
therefore has to assume a tree may hold anything — nested `.exe`/`.dll` files
needing `osslsigncode`, Mach-O binaries and `.app`/`.dmg`/`.pkg` bundles
needing `codesign`, or `.jar` files needing `jarsigner` — and requires **all**
signing toolchains, including `codesign.bzl` and jarsigner, even when nothing
in the tree turns out to need them.

Individual files do not have this problem. A file's signer is known exactly, so
only the toolchains actually selected are required: signing a single
`cc_binary` built for Linux asks for cosign and nothing else.

If you do not want to register signers you will never use, name the one you
need explicitly and no other native signer is required:

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
    tool = "auto",  # auto | osslsigncode | codesign | cosign | jarsigner
)
```

### What a `sign` target produces

Each source keeps its own shape. A file is signed into a **file**, a directory
into a **directory artifact**, both under the same relative path the wrapped
target used, below `<name>.signed/` (or the `out` you name). The directory
itself is not an output; the files inside it are. So a target wrapping one
`.exe` is that one signed `.exe`, and nothing else has to be unpacked to get
at it.

Signing with a detached signature adds files, because that is what such a
signature is: a source signed with `cosign sign-blob` is accompanied by its
`.sig` and `.bundle.json`, beside the original. A source signed natively
(`osslsigncode`, `codesign`) has the signature embedded in the artifact, so
the signed artifact is the whole output:

| Source | Signer | Outputs |
| --- | --- | --- |
| `app.exe` | osslsigncode | `app.exe` |
| `app.jar` | jarsigner | `app.jar` |
| `notes.md` | cosign | `notes.md`, `notes.md.sig`, `notes.md.bundle.json` |
| `some_dir/` | per file, inside | `some_dir/` |

### How a signer is chosen

Every signer decision is made while the build graph is built, never while the
action runs. It has to be: a detached signature is *extra files*, and a rule's
outputs have to be declared before anything is built, so "which signer" and
"which outputs" are the same question and both are answered up front. Each file
is therefore signed exactly once, by one signer, with outputs that are known
before the build starts.

Under `tool = "auto"` a file is routed by two pieces of evidence:

1. **The rule that produces it.** A file built by a rule known to produce
   native binaries is a native binary. Which *format* comes from the
   configuration that rule was analysed in — a binary is a PE because it was
   built for Windows, not because it starts with `MZ` — so a cross-compiled
   binary is classified correctly even though the target doing the signing is
   built for something else.
2. **Its name**, for files no rule spoke for: prebuilt artifacts committed to
   the repository, downloads, `genrule` output. This is also the only
   possible evidence for the formats Authenticode defines *by file type* --
   PowerShell and JavaScript scripts, `.msi` and `.cab` installers, `.cat`
   catalogs, `.dmg`/`.pkg` images -- since no compiler emits those, so no
   rule kind can describe them.

**The order matters, and it is strict.** A rule in the table speaks for its
outputs conclusively, including when what it says is that they are *not*
native binaries. A name is never allowed to overrule it. `native_binary` is
why: it names its output `<name>.exe` on every platform, Linux included, so a
name consulted afterwards would hand an ordinary ELF to osslsigncode.

Anything neither step answers for gets a detached cosign signature. That
includes a prebuilt binary with no extension, which cannot be distinguished
from any other opaque blob without opening it — name it with `tool` if it
needs native signing.

An explicit `tool` skips both steps and is used as given.

#### Teaching it about a ruleset

The rules that produce native binaries are listed in
[`signing/private/binary_kinds.bzl`](signing/private/binary_kinds.bzl), one row
per rule, keyed by the rule's name as a string:

```starlark
RULE_KINDS = {
    "cc_binary": executable(),           # the rule's executable output
    "cc_shared_library": all_outputs(),  # every output is a native library
    "csharp_library": all_outputs(format = PE),  # PE on every platform
    "java_binary": jar_outputs(),        # only the `.jar`, not its launcher
    "_copy_file": forward("src"),        # bytes come from another target
    "py_binary": not_native("a bootstrap script"),
}
```

Because the keys are strings, adding a ruleset costs nothing to builds that do
not use it — the table names `go_binary` without `rules_go` being in the module
graph, and has no dependencies of its own to keep in sync. It currently covers
rules_cc, rules_go, rules_rust, rules_swift, rules_apple, rules_dotnet,
rules_zig, rules_d, rules_haskell, the core Bazel Java rules, rules_kotlin,
rules_scala, bazel_skylib and aspect_bazel_lib.

A rule that is absent produces nothing signable, which is the right answer for
`py_binary`, `sh_binary` and every other launcher script. `not_native()` rows
record that an omission was a decision rather than an oversight.

`forward` is what keeps copies, renames and platform wrappers transparent: a
binary does not stop being a binary for having been copied, so a `cc_binary`
behind a platform transition behind a copy is still recognised. Forwarding
matches by `File` identity where it can — which is exact, and is why one
binary in a `filegroup` full of data files is still found — and falls back to
pairing in order only for rules that mint new `File`s.

A rule can also answer for itself, instead of being described from the outside,
by returning a `BinaryFormatInfo` mapping its own `File`s to `"pe"` or
`"macho"`. The aspect leaves any rule that does so alone. See
[`signing/tests/cross.bzl`](signing/tests/cross.bzl) for a worked example.

### Choosing which files get a detached signature

The table above is what `detached_signatures = "auto"`, the default, decides
per source. The other two modes answer for every source at once, which takes
the source's name out of the question entirely:

```starlark
sign(
    name = "signed_release",
    src = ":release_files",
    certificate = ":release_cert",

    # "auto"    the default: whatever a source cannot embed, it gets beside it
    # "always"  every source gets a .sig and .bundle.json
    # "never"   no source does
    detached_signatures = "always",
)
```

`"always"` makes a target's outputs predictable from its sources alone — three
files per source, whatever they are called — and gives natively signed
artifacts a second, detached signature as well, applied over the artifact as
it will be delivered so both verify against the same bytes. The cost is a
cosign invocation per file (plus a timestamp or transparency-log round trip
each, if those are on) and a second signature whose key and verification
instructions you have to publish alongside the first. It requires a
`certificate`, since a `.sig` that was promised cannot be silently skipped.

`"never"` leaves only what native signers embed. Anything without a native
signer is then copied through **unsigned** rather than merely unverified, so
reach for it when you are signing binaries and deliberately not signing
anything else.

Because a file's outputs are known before it is signed, a target that wraps a
single source can be referenced directly — `$(rootpath :signed_installer)` is
the signed installer. A target that wraps several has several outputs, so use
`$(rootpaths ...)`, or `filegroup`/`select` on what you need.

For `oci_image` sources, `sign` copies the OCI layout output, signs the root manifest blob with `cosign sign-blob` (when a key resolves), and writes the signature bundle under `signatures/` in the output layout. Other directory artifacts retain their complete directory structure and are traversed recursively, signing individual files selected by extension (for example, `.exe` and `.dll`) and, for files with no extension, by parsing their headers with [LIEF](https://lief.re/). Files without a native signer receive colocated cosign `.sig` and `.bundle.json` outputs. Files inside a tree are the one place headers are still read: a tree's contents do not exist until the action runs, so nothing inside it can be classified from its producing rule, and nothing inside it is declared file by file either — which is what makes reading them safe there and not elsewhere. Note that with `tool = "auto"` any directory artifact requires every signing toolchain to be registered — see [Setup](#setup).

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
just proceed as if no certificate had been configured. The exception is a
source whose detached signature was declared as an output: since a `.sig` that
was promised cannot be quietly left out, and an empty one would be worse than
none, that combination fails with a message naming the certificate. Drop the
`certificate` attribute to build unsigned copies deliberately. An unresolved `{KEY}`
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
to four different signers. One certificate can drive all four, provided it is
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

`jarsigner` is the other signer that cannot consume a certificate directly —
it only ever reads a keystore. `sign` bridges this the same way, building a
throwaway PKCS#12 keystore from the certificate during the action, under an
alias `rules_signing` itself controls, so the original certificate's own
alias (or a PEM's lack of one) never has to be recovered. Building that
keystore needs the optional openssl toolchain (below) regardless of whether
the certificate started as PEM or PKCS#12, since jarsigner has nothing to
consume until the keystore exists.

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
`cosign` or `jarsigner` fails with an actionable message rather than a cryptic
error from either.

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
keep their layout" case, call `sign_action` and skip building the command
line: pair it with `signed_outputs` to declare one output per source the way
`sign` does, or hand it an `out_dir` tree artifact to collect everything into
a single directory instead.

## Standalone consumer module test

A real consumer-module workspace lives at `usagetest/` with its own `MODULE.bazel`.

```bash
cd usagetest
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs //:signed_oci_image
```
