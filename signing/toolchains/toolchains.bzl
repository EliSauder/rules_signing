_CODESIGN_BZL_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"

def _codesign_bzl_tool_impl(ctx):
    tc = ctx.toolchains[_CODESIGN_BZL_TOOLCHAIN]
    if tc == None:
        fail(
            "rules_signing: the default codesign adapter requires a codesign.bzl toolchain; " +
            "register it with register_toolchains(\"@codesign.bzl//toolchain:all\"), " +
            "or supply an rcodesign binary with codesign_toolchain(codesign = ...).",
        )
    tool = getattr(tc, "codesign", None)
    if tool == None:
        fail("rules_signing: the resolved codesign.bzl toolchain does not expose a codesign executable")
    return [DefaultInfo(
        files = depset([tool]),
        runfiles = ctx.runfiles(
            files = [tool],
            transitive_files = getattr(tc, "data", depset()),
        ),
    )]

codesign_bzl_tool = rule(
    implementation = _codesign_bzl_tool_impl,
    doc = "Exposes the rcodesign binary selected by codesign.bzl's toolchain resolution.",
    toolchains = [config_common.toolchain_type(_CODESIGN_BZL_TOOLCHAIN, mandatory = False)],
)

def _codesign_toolchain_impl(ctx):
    tool = ctx.file.codesign
    data = depset(
        [tool] + ctx.files.data,
        transitive = [ctx.attr.codesign[DefaultInfo].default_runfiles.files],
    )
    return [
        platform_common.ToolchainInfo(tool = tool, data = data),
        DefaultInfo(files = data, runfiles = ctx.runfiles(transitive_files = data)),
    ]

codesign_toolchain = rule(
    implementation = _codesign_toolchain_impl,
    doc = """Provides an optional Apple signing toolchain using rcodesign.

By default, codesign.bzl selects the executable for the execution platform.
Set codesign to a custom rcodesign binary to bypass that resolution entirely.
Apple's /usr/bin/codesign has a different CLI and is not supported by this adapter.
""",
    attrs = {
        "codesign": attr.label(
            default = "@rules_signing//signing/toolchains:codesign_bzl",
            cfg = "exec",
            allow_single_file = True,
            doc = "An rcodesign executable, or a target exposing one file and its runfiles.",
        ),
        "data": attr.label_list(
            cfg = "exec",
            allow_files = True,
            doc = "Additional runtime files needed by the rcodesign binary.",
        ),
    },
    provides = [platform_common.ToolchainInfo],
)

def _jarsigner_toolchain_impl(ctx):
    runtime = getattr(ctx.attr.java_runtime[platform_common.ToolchainInfo], "java_runtime", None)
    if runtime == None:
        fail("jarsigner_toolchain: java_runtime must expose a JDK in ToolchainInfo.java_runtime")

    tool = None
    for f in runtime.files.to_list():
        if f.basename in ["jarsigner", "jarsigner.exe"]:
            tool = f
            break
    if tool == None:
        fail(
            "jarsigner_toolchain: java_runtime {} does not contain jarsigner; ".format(ctx.attr.java_runtime.label) +
            "use a full JDK, not a JRE. For the default runtime, select a JDK " +
            "with --tool_java_runtime_version.",
        )

    return [
        platform_common.ToolchainInfo(
            tool = tool,
            data = runtime.files,
            java_runtime = runtime,
        ),
        DefaultInfo(
            files = runtime.files,
            runfiles = ctx.runfiles(transitive_files = runtime.files),
        ),
    ]

jarsigner_toolchain = rule(
    implementation = _jarsigner_toolchain_impl,
    doc = """Adapts a Bazel/rules_java JDK runtime to the optional jarsigner toolchain.

The default runtime uses Bazel's Java toolchain resolution for the execution
platform, controlled by --tool_java_runtime_version. Set java_runtime to a
java_runtime target to use a specific local, downloaded, or custom JDK instead.
ToolchainInfo exposes tool (jarsigner), data (the full JDK), and java_runtime.
""",
    attrs = {
        "java_runtime": attr.label(
            default = "@bazel_tools//tools/jdk:current_java_runtime",
            cfg = "exec",
            providers = [platform_common.ToolchainInfo],
            doc = "A Java runtime exposing ToolchainInfo.java_runtime, built for the execution platform.",
        ),
    },
    provides = [platform_common.ToolchainInfo],
)

def _cosign_toolchain_impl(ctx):
    tool = ctx.file.cosign
    return [
        platform_common.ToolchainInfo(
            tool = tool,
            data = depset([tool]),
        ),
        DefaultInfo(files = depset([tool])),
    ]

cosign_toolchain = rule(
    implementation = _cosign_toolchain_impl,
    attrs = {
        "cosign": attr.label(
            cfg = "exec",
            allow_single_file = True,
            mandatory = True,
        ),
    },
    provides = [platform_common.ToolchainInfo],
)

def _osslsigncode_toolchain_impl(ctx):
    tool = ctx.file.osslsigncode
    return [
        platform_common.ToolchainInfo(
            tool = tool,
            data = depset([tool]),
            default_timestamp_url = ctx.attr.default_timestamp_url,
        ),
        DefaultInfo(files = depset([tool])),
    ]

osslsigncode_toolchain = rule(
    implementation = _osslsigncode_toolchain_impl,
    attrs = {
        "osslsigncode": attr.label(
            cfg = "exec",
            allow_single_file = True,
            mandatory = True,
        ),
        "default_timestamp_url": attr.string(default = ""),
    },
    provides = [platform_common.ToolchainInfo],
)

def _openssl_toolchain_impl(ctx):
    tool = ctx.file.openssl
    return [
        platform_common.ToolchainInfo(
            tool = tool,
            # Windows' openssl.exe dynamically loads libcrypto/libssl DLLs
            # from its own directory; `data` carries those alongside `tool`
            # so callers can add them as action inputs without needing to
            # know that Windows needs anything beyond the executable itself.
            data = depset([tool] + ctx.files.data),
        ),
        DefaultInfo(files = depset([tool] + ctx.files.data)),
    ]

openssl_toolchain = rule(
    implementation = _openssl_toolchain_impl,
    doc = "Optional toolchain used to convert PKCS#12 signing material to PEM.",
    attrs = {
        "openssl": attr.label(
            cfg = "exec",
            allow_single_file = True,
            mandatory = True,
        ),
        "data": attr.label_list(
            cfg = "exec",
            allow_files = True,
            doc = "Extra files openssl needs alongside it at runtime " +
                  "(e.g. Windows' libcrypto/libssl DLLs).",
        ),
    },
    provides = [platform_common.ToolchainInfo],
)
