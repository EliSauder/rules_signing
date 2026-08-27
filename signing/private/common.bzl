def default_out(ctx, src):
    if ctx.attr.out:
        return ctx.attr.out
    base = src.basename
    dot = base.rfind(".")
    if dot > 0:
        return "{}.signed{}".format(base[:dot], base[dot:])
    return "{}.signed".format(base)

def cert_info(ctx):
    if not ctx.attr.certificate:
        return None
    return ctx.attr.certificate[SigningCertificateInfo]

def run_signer(ctx, script, toolchain, source, out, args, extra_inputs, mnemonic, progress):
    inputs = [src, script]
    inputs.extend(extra_inputs)
    ctx.actions.run_shell(
        inputs = depset(inputs),
        outputs = [out],
        command = 'exec bash "{}" "$@"'.format(script.path),
        arguments = [args],
        mnemonic = mnemonic,
        progress_message = "{} {}".format(progress, src.short_path),
        use_default_shell_env = True,
    )

def add_cert_args(ctx, args, info):
    extra = [ctx.file._stamp_lib]
    args.add("--stamp-lib", ctx.file._stamp_lib)

    if info == None:
        return extra

    if info.certificate != None:
        args.add("--cert-file", info.certificate)
        extra.append(info.certificate)
    if info.cert:
        args.add("--cert-template", info.cert)
    args.add("--cert-encoding", info.cert_encoding or "path")
    if info.password:
        args.add("--password-template", info.password)
    if info.password_env:
        args.add("--password-env", info.password_env)
    if info.identity:
        args.add("--identity-template", info.identity)

    for k, v in info.stamp_defaults.items():
        args.add("--stamp-default", "{}={}".format(k, v))

    if cert_needs_stamp(info):
        args.add("--info-file", ctx.info_file)
        args.add("--version-file", ctx.version_file)
        extra.append(ctx.info_file)
        extra.append(ctx.version_file)

    return extra

STAMP_LIB_ATTR = {
    "_stamp_lib": attr.label(
        default = "//signing/private/tools:stamp.sh",
        allow_single_file = True,
    ),
}
