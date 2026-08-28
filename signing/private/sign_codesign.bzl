load(
    "//signing/private:common.bzl",
    "add_cert_args",
    "cert_info",
    "default_out",
)
load("//signing:providers.bzl", "SigningCertificateInfo")

_CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"

def _sign_codesign_impl(ctx):
    src = ctx.file.src
    out = ctx.actions.declare_file(default_out(ctx, src))
    info = cert_info(ctx)

    tc = ctx.toolchains[_CODESIGN_TOOLCHAIN]
    if tc == None:
        fail("codesign toolchain is required but was not resolved")
    tool = ""
    default_timestamp_url = ""
    if hasattr(tc, "codesign"):
        cs = tc.codesign
        if hasattr(cs, "tool"):
            tool = cs.tool.path
        if hasattr(cs, "default_timestamp_url"):
            default_timestamp_url = cs.default_timestamp_url
    elif hasattr(tc, "tool"):
        tool = tc.tool.path
        if hasattr(tc, "default_timestamp_url"):
            default_timestamp_url = tc.default_timestamp_url
    if not tool:
        fail("codesign toolchain is resolved but does not expose an executable tool")

    args = ctx.actions.args()
    args.add("--mode", "codesign")
    args.add("--codesign-tool", tool)
    args.add("--in", src)
    args.add("--out", out)
    if ctx.attr.options:
        args.add("--options", ",".join(ctx.attr.options))
    if ctx.file.entitlements:
        args.add("--entitlements", ctx.file.entitlements.path)

    ts_url = ctx.attr.timestamp_url or default_timestamp_url
    if ts_url:
        args.add("--timestamp-url", ts_url)

    extra = add_cert_args(ctx, args, info)
    if ctx.file.entitlements:
        extra.append(ctx.file.entitlements)

    inputs = [src] + extra
    tools = [ctx.executable._tool]
    if ctx.file.entitlements:
        inputs.append(ctx.file.entitlements)
    if hasattr(tc, "codesign") and hasattr(tc.codesign, "tool"):
        inputs.append(tc.codesign.tool)
    elif hasattr(tc, "tool"):
        inputs.append(tc.tool)

    ctx.actions.run(
        executable = ctx.executable._tool,
        inputs = depset(inputs),
        tools = tools,
        outputs = [out],
        arguments = [args],
        mnemonic = "SignCodesign",
        progress_message = "Signing (Apple) {}".format(src.short_path),
    )

    return [DefaultInfo(files = depset([out]))]

sign_codesign = rule(
    implementation = _sign_codesign_impl,
    doc = "Signs Apple artifacts with codesign or passes through when unresolved.",
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(),
        "certificate": attr.label(
            providers = [[SigningCertificateInfo]],
        ),
        "options": attr.string_list(
            default = ["runtime"],
            doc = "codesign --options values.",
        ),
        "timestamp_url": attr.string(),
        "entitlements": attr.label(allow_single_file = True),
        "_tool": attr.label(
            default = "//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = [
        config_common.toolchain_type(_CODESIGN_TOOLCHAIN),
    ],
)
