"""Test-only rules that build signable fixtures and expose signing binaries.

The signature-verification tests need two things Bazel does not hand out
directly: macOS bundle inputs that can be produced on any host, and the
`rcodesign` binary as an ordinary dependency so a test can shell out to it.
"""

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")
load(
    "//signing:actions.bzl",
    "SIGNING_ATTRS",
    "SIGNING_TOOLCHAINS",
    "signing_argv",
    "signing_context",
)

_CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"

def _app_bundle_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    binary = ctx.file.binary
    plist = ctx.file.info_plist

    ctx.actions.run_shell(
        inputs = [binary, plist],
        outputs = [out],
        command = """
set -e
mkdir -p "$1/Contents/MacOS" "$1/Contents/Resources"
cp "$2" "$1/Contents/MacOS/$4"
cp "$3" "$1/Contents/Info.plist"
""",
        arguments = [out.path, binary.path, plist.path, ctx.attr.executable_name],
        mnemonic = "MakeAppBundle",
        progress_message = "Assembling app bundle for {}".format(ctx.label),
    )
    return [DefaultInfo(files = depset([out]))]

app_bundle = rule(
    implementation = _app_bundle_impl,
    doc = """Assembles a minimal macOS `.app` bundle as a directory artifact.

rules_apple would be the natural way to build one, but it drives Xcode and so
only works on a macOS host. Signing a bundle is host independent, and this
ruleset's CI signs on Linux and Windows too, so the bundle is assembled
directly from a cross-compiled Mach-O binary and an `Info.plist`. That is
enough for rcodesign: it reads `CFBundleExecutable`, signs the executable it
names, and writes `Contents/_CodeSignature/CodeResources`.
""",
    attrs = {
        "binary": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "Mach-O binary placed in Contents/MacOS.",
        ),
        "info_plist": attr.label(
            allow_single_file = True,
            mandatory = True,
            doc = "Bundle Info.plist. Its CFBundleExecutable must match `executable_name`.",
        ),
        "executable_name": attr.string(
            mandatory = True,
            doc = "Name to give the binary inside Contents/MacOS.",
        ),
    },
)

def _codesign_tool_impl(ctx):
    toolchain = ctx.toolchains[_CODESIGN_TOOLCHAIN]
    if toolchain == None:
        fail(
            "the codesign toolchain is not registered; add " +
            "register_toolchains(\"@codesign.bzl//toolchain:all\")",
        )

    tool = toolchain.codesign
    return [DefaultInfo(
        files = depset([tool]),
        runfiles = ctx.runfiles(files = [tool]),
    )]

codesign_tool = rule(
    implementation = _codesign_tool_impl,
    doc = """Exposes the toolchain's rcodesign binary as a plain dependency.

cosign and osslsigncode are fetched into repositories that also publish a
`filegroup`, so a test can depend on them by label. The codesign toolchain has
no such filegroup and is selected per execution platform, so reaching the
binary requires toolchain resolution inside a rule.
""",
    toolchains = [config_common.toolchain_type(_CODESIGN_TOOLCHAIN, mandatory = False)],
)

# ---------------------------------------------------------------------------
# Embedded signing fixture
#
# Proves the `//signing:actions.bzl` API works for rules that cannot use a
# separate `sign` action at all. NSIS is the motivating case: its uninstaller
# only exists during the `makensis` run, and is signed through the
# `!uninstfinalize` hook, which hands a signer a path and expects the file at
# that path to come back signed. So the signer has to run *inside* another
# tool's action, as a grandchild process, against an artifact that does not
# exist at analysis time.
#
# This fixture reproduces exactly that shape: an action owned by an unrelated
# executable produces a PE binary and then invokes the command built by
# `signing_argv` on it in place. sign_verify_test checks the result with
# osslsigncode's own verifier, so a signature produced this way is held to the
# same standard as one from the `sign` rule.
# ---------------------------------------------------------------------------

def _embedded_sign_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".exe")

    # No `srcs`: what gets signed is produced by this action, so the required
    # toolchain has to be stated outright rather than inferred.
    sctx = signing_context(
        ctx,
        require = ["osslsigncode"],
        require_reason = "this rule always emits a PE executable",
    )

    argv = signing_argv(sctx, infile = out)

    ctx.actions.run_shell(
        command = """
set -eu
cp "$1" "$2"
chmod +w "$2"
shift 2
exec "$@"
""",
        arguments = [ctx.file.binary.path, out.path] + argv,
        inputs = depset([ctx.file.binary], transitive = [sctx.inputs]),
        tools = sctx.tools,
        outputs = [out],
        env = sctx.env,
        mnemonic = "EmbeddedSign",
        progress_message = "Building and signing {} in one action".format(ctx.label),
    )
    return [DefaultInfo(files = depset([out]))]

embedded_sign = rule(
    implementation = _embedded_sign_impl,
    doc = "Test fixture: produces a PE and signs it in place from within the " +
          "same action, the way a packaging tool's finalize hook would.",
    attrs = dict({
        "binary": attr.label(allow_single_file = True, mandatory = True),
        # SIGNING_ATTRS deliberately excludes the stamp attributes, so the
        # rule declares them itself -- exactly as a consumer would.
    }, **dict(SIGNING_ATTRS, **STAMP_ATTRS)),
    toolchains = SIGNING_TOOLCHAINS,
)
