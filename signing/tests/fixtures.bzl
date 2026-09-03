"""Test-only rules that build signable fixtures and expose signing binaries.

The signature-verification tests need two things Bazel does not hand out
directly: macOS bundle inputs that can be produced on any host, and the
`rcodesign` binary as an ordinary dependency so a test can shell out to it.
"""

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
