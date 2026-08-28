load("//signing:providers.bzl", "SigningCertificateInfo")

def _certificate_impl(ctx):
    cert_file = ctx.file.certificate_file
    return [
        DefaultInfo(files = depset([cert_file] if cert_file else [])),
        SigningCertificateInfo(
            certificate = cert_file,
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
