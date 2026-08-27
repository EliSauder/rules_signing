load(
    "//signing/private:common.bzl",
    "STAMP_LIB_ATTR",
    "add_cert_args",
    "cert_info",
    "default_out",
    "run_signer",
)

_CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type",

def _sign_apple_impl(ctx):
    tc = ctx.toolchains[_CODESIGN_TOOLCHAIN].codesign
    src = ctx.file.src
    out = ctx.actions.declare_file(default_out(ctx, src))
    info = cert_info(ctx)

    args = ctx.actions.args()
    args.add("--tool", tc.tool)
    args.add("--in", src)
    args.add("--out", out)
    if ctx.attr.options:
        args.add("--options", ",".join(ctx.attr.options))
    if ctx.attr.entitlements:
        args.add("--entitlements", ctx.file.entitlements)
    if tc.default_timestamp_url:
        args.add("--timestamp-url", tc.default_timestamp_url)

    extra = add_cert_args(ctx, args, info)
    if ctx.file.entitlements:
        extra.append(ctx.file.entitlements)

    run_signer(
        ctx,
        script = ctx.file._script,
        tc = tc,
        src = src,
        out = out,
        args = args,
        extra_inputs = extra,
        mnemonic = "SignApple",
        progress = "Signing (Apple)",
    )
    return [DefaultInfo(files = depset([out]))]

sign_apple = rule(
    implementation = _sign_apple_impl,
    doc = "Signs an Apple binary/bundle with codesign, or passes it through.",
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(),
        "certificate": attr.label(),
        "options": attr.string_list(
            default = ["runtime"],
            doc = "codesign --options values (e.g. 'runtime' for hardened runtime).",
        ),
        "entitlements": attr.label(allow_single_file = True),
        "_script": attr.label(
            default = "//signing/private/tools:sign_codesign.sh",
            allow_single_file = True,
        ),
    } | STAMP_LIB_ATTR,
    toolchains = [
        _CODESIGN_TOOLCHAIN,
    ],
)
