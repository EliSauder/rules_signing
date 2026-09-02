load("//signing:providers.bzl", "SigningCertificateInfo")

def _certificate_impl(ctx):
    cert_file = ctx.file.certificate_file

    # Everything the certificate is made of. The signing action adds these to
    # its own inputs from the provider, but a `certificate` target is also a
    # perfectly ordinary file target: it can be built on its own, listed in a
    # filegroup, or referenced from `srcs`/`data`. Omitting the chain there
    # would hand those consumers a certificate that cannot be verified.
    files = [f for f in (cert_file, ctx.file.ca_file) if f != None]

    return [
        DefaultInfo(
            files = depset(files),
            runfiles = ctx.runfiles(files = files),
        ),
        SigningCertificateInfo(
            certificate = cert_file,
            ca_file = ctx.file.ca_file,
            cert = ctx.attr.certificate,
            cert_encoding = ctx.attr.certificate_encoding,
            password = ctx.attr.password,
            password_env = ctx.attr.password_env,
            identity = ctx.attr.identity,
            stamp_defaults = ctx.attr.stamp_defaults,
        ),
    ]

certificate = rule(
    implementation = _certificate_impl,
    doc = "Produces SigningCertificateInfo for signing rules.",
    attrs = {
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
    },
)
