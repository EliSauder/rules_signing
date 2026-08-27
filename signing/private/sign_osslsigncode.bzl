load(
    "//signing/private:common.bzl",
    "STAMP_LIB_ATTR",
    "add_cert_args",
    "cert_info",
    "default_out",
    "run_signer",
)

_OSSLSIGNCODE_TOOLCHAIN = "//signing/toolchains:osslsigncode_toolchain_type"

def _sign_osslsigncode_impl(ctx):
    tc = ctx.toolchains[_OSSLSIGNCODE_TOOLCHAIN]
    src = ctx.file.src
    out = ctx.actions.declare_file(default_out(ctx, src))
    info = cert_info(ctx)

    args = ctx.actions.args()
    args.add("--tool", tc.osslsigncode)
    args.add("--in", src)
    args.add("--out", out)

    ts_url = ctx.attr.timestamp_url or tc.default_timestamp_url
    if ts_url:
        args.add("--timestamp-url", ts_url)
    if ctx.attr.description:
        args.add("--name", ctx.attr.description)
    if ctx.attr.url:
        args.add("--url", ctx.attr.url)

    extra = add_cert_args(ctx, args, info)

    run_signer(
        ctx,
        script = ctx.file._script,
        tc = tc,
        src = src,
        out = out,
        args = args,
        extra_inputs = extra,
        mnemonic = "SignPE",
        progress = "Signing (PE)",
    )

    return [DefaultInfo(files = depset([out]))]

sign_osslsigncode = rule(
    implementation = sign_osslsigncode_impl,
    doc = "Signs an artifact supported by osslsigncode, or passes it through if no cert resolves.",
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.string(),
        "certificate": attr.label(
            providers = [
                SigningCertificateInfo,
            ],
        ),
        "timestamp_url": attr.string(),
        "description": attr.string(doc = "Signature description (osslsigncode -n)."),
        "url": attr.string(doc = "Publisher URL (osslsigncode -i)."),
        "_script": attr.label(
            default = "//signing/private/tools:sign_osslsigncode.sh",
            allow_single_file = True,
        ),
    } | STAMP_LIB_ATTR,
    toolchains = [
        _OSSLSIGNCODE_TOOLCHAIN,
    ],
)
