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
            data = depset([tool]),
        ),
        DefaultInfo(files = depset([tool])),
    ]

openssl_toolchain = rule(
    implementation = _openssl_toolchain_impl,
    doc = "Optional toolchain used to convert PKCS#12 signing material to PEM.",
    attrs = {
        "openssl": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
    },
    provides = [platform_common.ToolchainInfo],
)
