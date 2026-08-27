def _signing_certificate_impl(ctx):
    cert_file = None
    cert_type = ""
    password = ctx.attr.password

    return [
        DefaultInfo(files = depset([x for x in [ctx.file.certificate_file] if x != None)),
        SigningCertificateInfo(
            certificate = ctx.attr.certificate,
            certificate_encoding = ctx.attr.certificate_encoding,
            certificate_file = ctx.attr.certificate_file,
            certificate_file_type = ctx.attr.certificate_file_type,
            password = ctx.attr.password,
            password_env = ctx.attr.password_env,
            identity = ctx.attr.identity,
            stamp_defaults = ctx.attr.stamp_defaults,
        )
    ]

signing_certificate = rule(
    implementation = _signing_certificate_impl,
    doc = "Produces a SigningCertificateInfo for use by sign().",
    attrs = {
        "certificate": attr.string(
            doc = "Cert template with optional {KEY} placeholders. Empty => passthrough.",
        ),
        "certificate_encoding": attr.string(
            default = "path",
            values = ["path", "base64"],
        ),
        "certificate_file": attr.label(
            allow_single_file = [".p12", ".pfx", ".pem"],
        ),
        "certificate_file_type": attr.string(
            default = "pkcs12",
            values = ["pkcs12", "pem"],
        ),
        "password": attr.string(doc = "Cert password; may contain {KEY} placeholders."),
        "password_env": attr.string(doc = "Env var name holding the cert password."),
        "identity": attr.string(doc = "Apple codesign identity; may contain {KEY}."),
        "stamp_defaults": attr.string_dict(
            doc = "Default values keyed by stamp name for unresolved {KEY}s.",
        ),
        "_gen_cert": attr.label(
            default = "//signing/private/tools:gen_cert.sh",
            allow_single_file = True,
        ),
    },
    toolchains = [
        config_common.toolchain_type(OPENSSL_TOOLCHAIN_TYPE, mandatory = False),
    ],
)
