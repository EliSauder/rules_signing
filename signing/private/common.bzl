load("//signing:providers.bzl", "SigningCertificateInfo")

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

def cert_needs_stamp(info):
    if info == None:
        return False
    for v in [info.cert, info.password, info.identity]:
        if v and "{" in v:
            return True
    return False

def add_cert_args(ctx, args, info):
    extra = []

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
