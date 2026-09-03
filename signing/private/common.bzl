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

def add_cert_args(args, info, stamp):
    """Adds certificate-related args/inputs to `args`.

    Args:
        args: an Args object to append to.
        info: a SigningCertificateInfo, or None.
        stamp: the result of `@bazel_lib//lib:stamping.bzl`'s `maybe_stamp(ctx)`
            (a struct with `stable_status_file`/`volatile_status_file`), or
            None if stamping is disabled for this target/build. Only consulted
            when a certificate template actually needs stamp values.

    Returns:
        A list of extra Files that must be added to the action's inputs.
    """
    extra = []

    if info == None:
        return extra

    if info.certificate != None:
        args.add("--cert-file", info.certificate)
        extra.append(info.certificate)
    if getattr(info, "ca_file", None) != None:
        args.add("--ca-file", info.ca_file)
        extra.append(info.ca_file)
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

    if cert_needs_stamp(info) and stamp:
        args.add("--info-file", stamp.stable_status_file)
        args.add("--version-file", stamp.volatile_status_file)
        extra.append(stamp.stable_status_file)
        extra.append(stamp.volatile_status_file)

    return extra
