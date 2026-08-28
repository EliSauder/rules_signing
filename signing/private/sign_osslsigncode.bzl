load(
    "//signing/private:common.bzl",
    "add_cert_args",
    "cert_info",
    "default_out",
)
load("//signing:providers.bzl", "SigningCertificateInfo")

_OSSLSIGNCODE_TOOLCHAIN = "//signing/toolchains:osslsigncode_toolchain_type"

def _sign_osslsigncode_impl(ctx):
    src = ctx.file.src
    out = ctx.actions.declare_file(default_out(ctx, src))
    info = cert_info(ctx)

    tc = ctx.toolchains[_OSSLSIGNCODE_TOOLCHAIN]
    if tc == None or not hasattr(tc, "tool"):
        fail("osslsigncode toolchain is required but was not resolved")
    tool = tc.tool.path
    default_timestamp_url = tc.default_timestamp_url if hasattr(tc, "default_timestamp_url") else ""

    args = ctx.actions.args()
    args.add("--mode", "osslsigncode")
    args.add("--osslsigncode-tool", tool)
    args.add("--in", src)
    args.add("--out", out)

    ts_url = ctx.attr.timestamp_url or default_timestamp_url
    if ts_url:
        args.add("--timestamp-url", ts_url)
    if ctx.attr.description:
        args.add("--name", ctx.attr.description)
    if ctx.attr.url:
        args.add("--url", ctx.attr.url)

    extra = add_cert_args(ctx, args, info)

    inputs = [src] + extra
    tools = [ctx.executable._tool]
    inputs.append(tc.tool)

    ctx.actions.run(
        executable = ctx.executable._tool,
        inputs = depset(inputs),
        tools = tools,
        outputs = [out],
        arguments = [args],
        mnemonic = "SignOsslSignCode",
        progress_message = "Signing (PE) {}".format(src.short_path),
    )

    return [DefaultInfo(files = depset([out]))]

sign_osslsigncode = rule(
    implementation = _sign_osslsigncode_impl,
    doc = "Signs osslsigncode-compatible artifacts or passes through when unresolved.",
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(),
        "certificate": attr.label(
            providers = [[SigningCertificateInfo]],
        ),
        "timestamp_url": attr.string(),
        "description": attr.string(doc = "Signature description (osslsigncode -n)."),
        "url": attr.string(doc = "Publisher URL (osslsigncode -i)."),
        "_tool": attr.label(
            default = "//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = [
        config_common.toolchain_type(_OSSLSIGNCODE_TOOLCHAIN),
    ],
)
