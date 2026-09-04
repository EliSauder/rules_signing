load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load("//signing:providers.bzl", "SigningCertificateInfo")

def _template_needs_stamp(template):
    return bool(template) and "{" in template

def _resolve_certificate(ctx):
    """Renders `certificate`/`certificate_encoding` into a File, if set.

    Runs the resolution once per `certificate` target rather than once per
    `sign` action that consumes it, using this rule's own `stamp` attribute
    (via `maybe_stamp`) to decide whether real workspace status values or
    `stamp_defaults` fill in any `{KEY}` placeholder.
    """

    if not ctx.attr.certificate:
        return None

    out = ctx.actions.declare_file(ctx.label.name + ".resolved_cert")
    args = ctx.actions.args()
    args.add("--mode", "resolve-cert")
    args.add("--cert-template", ctx.attr.certificate)
    args.add("--cert-encoding", ctx.attr.certificate_encoding)
    args.add("--out", out)
    for k, v in ctx.attr.stamp_defaults.items():
        args.add("--stamp-default", "{}={}".format(k, v))

    inputs = []
    if _template_needs_stamp(ctx.attr.certificate):
        stamp = maybe_stamp(ctx)
        if stamp:
            args.add("--info-file", stamp.stable_status_file)
            args.add("--version-file", stamp.volatile_status_file)
            inputs.extend([stamp.stable_status_file, stamp.volatile_status_file])

    ctx.actions.run(
        executable = ctx.executable._resolver,
        arguments = [args],
        inputs = depset(inputs),
        outputs = [out],
        mnemonic = "ResolveCertificate",
        progress_message = "Resolving stamped certificate for {}".format(ctx.label),
    )
    return out

def _certificate_impl(ctx):
    ca_file = ctx.file.ca_file

    # A direct `certificate_file` is already resolved; only a `certificate`
    # template (base64 blob or on-disk path, possibly stamped) needs an
    # action to turn into a File.
    resolved_cert = ctx.file.certificate_file
    if resolved_cert == None:
        resolved_cert = _resolve_certificate(ctx)

    # Everything the certificate is made of. The signing action adds these to
    # its own inputs from the provider, but a `certificate` target is also a
    # perfectly ordinary file target: it can be built on its own, listed in a
    # filegroup, or referenced from `srcs`/`data`. Omitting the chain there
    # would hand those consumers a certificate that cannot be verified.
    files = [f for f in (resolved_cert, ca_file) if f != None]

    return [
        DefaultInfo(
            files = depset(files),
            runfiles = ctx.runfiles(files = files),
        ),
        SigningCertificateInfo(
            certificate = resolved_cert,
            ca_file = ca_file,
            password = ctx.attr.password,
            password_env = ctx.attr.password_env,
            identity = ctx.attr.identity,
            stamp_defaults = ctx.attr.stamp_defaults,
        ),
    ]

certificate = rule(
    implementation = _certificate_impl,
    doc = "Produces SigningCertificateInfo for signing rules. Evaluates its " +
          "own `stamp` attribute to resolve a `certificate` template " +
          "(if used) into a real File once, independently of any `sign` " +
          "target(s) that consume it.",
    attrs = dict({
        "certificate": attr.string(
            doc = "Certificate/key template with optional {KEY} placeholders.",
        ),
        "certificate_encoding": attr.string(
            default = "path",
            values = ["path", "base64"],
            doc = "How to interpret `certificate` when provided.",
        ),
        "certificate_file": attr.label(
            allow_single_file = [".p12", ".pfx", ".pem", ".key"],
            doc = "Static certificate/key file.",
        ),
        "ca_file": attr.label(
            allow_single_file = [".pem", ".crt", ".cer", ".ca", ".p7b"],
            doc = "Optional PEM file holding the intermediate/root certificates " +
                  "that issued this certificate. The chain is embedded in the " +
                  "signature so verifiers can build a trust path back to the " +
                  "root without fetching it themselves. Ignored by cosign, " +
                  "which signs with a bare key rather than an X.509 chain.",
        ),
        "password": attr.string(
            doc = "Optional password template with {KEY} placeholders.",
        ),
        "password_env": attr.string(
            doc = "Optional env var name holding the cert password.",
        ),
        "identity": attr.string(
            doc = "Optional Apple codesign identity template with {KEY} placeholders.",
        ),
        "stamp_defaults": attr.string_dict(
            doc = "Fallback map for unresolved {KEY} placeholders.",
        ),
        "_resolver": attr.label(
            default = "@rules_signing//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    }, **STAMP_ATTRS),
)
