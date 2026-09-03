"""Test-only helper that builds a target for a specific target platform.

Tool detection must work on real executables, so the fixtures are genuinely
cross-compiled rather than assembled from handwritten headers. The output is
deliberately named without an extension: extensionless binaries (the norm for
Mach-O) are exactly the case that filename-based detection cannot handle.
"""

def _platform_transition_impl(_settings, attr):
    return {"//command_line_option:platforms": str(attr.platform)}

_platform_transition = transition(
    implementation = _platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _platform_binary_impl(ctx):
    src = ctx.file.binary
    out = ctx.actions.declare_file(ctx.label.name)

    # Copy rather than symlink so the runfile is a real file the test can read.
    ctx.actions.run_shell(
        inputs = [src],
        outputs = [out],
        command = 'cp "$1" "$2"',
        arguments = [src.path, out.path],
        mnemonic = "CopyPlatformBinary",
    )
    return [DefaultInfo(files = depset([out]))]

platform_binary = rule(
    implementation = _platform_binary_impl,
    attrs = {
        "binary": attr.label(
            allow_single_file = True,
            cfg = _platform_transition,
            mandatory = True,
            doc = "Binary to build for `platform`.",
        ),
        "platform": attr.label(
            mandatory = True,
            doc = "Target platform to build `binary` for.",
        ),
    },
    doc = "Builds `binary` for `platform` and copies it to an extensionless name.",
)
