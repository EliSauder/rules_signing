def _cosign_toolchain_impl(ctx):
    cosign = ctx.executable.cosign
    return [
        platform_common.ToolchainInfo(
            name = ctx.label.name,
            _cosign = cosign,
        ),
        DefaultInfo(files = depset([cosign])),
    ]

cosign_toolchain = rule(
    implementation = _cosign_toolchain_impl,
    attrs = {
        "cosign": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
    provides = [platform_common.ToolchainInfo],
)

def _osslsigncode_toolchain_impl(ctx):
    osslsigncode = ctx.executable.osslsigncode
    return [
        platform_common.ToolchainInfo(
            name = ctx.label.name,
            _osslsigncode = osslsigncode,
        ),
        DefaultInfo(files = depset([osslsigncode])),
    ]

osslsigncode_toolchain = rule(
    implementation = _osslsigncode_toolchain_impl,
    attrs = {
        "osslsigncode": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
    provides = [platform_common.ToolchainInfo],
)

def _openssl_toolchain_impl(ctx):
    openssl = ctx.executable.openssl
    return [
        platform_common.ToolchainInfo(
            name = ctx.label.name,
            _openssl = openssl,
        ),
        DefaultInfo(files = depset([openssl])),
    ]

openssl_toolchain = rule(
    implementation = _openssl_toolchain_impl,
    attrs = {
        "openssl": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
    provides = [platform_common.ToolchainInfo],
)
