"""Rules that re-express a `certificate` in another file format."""

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")
load("//signing:providers.bzl", "SigningCertificateInfo")
load("//signing/private:action.bzl", "COSIGN_TOOLCHAIN", "OPENSSL_TOOLCHAIN")
load("//signing/private:convert.bzl", "convert_certificate")

def _convert(ctx, fmt, outputs, out_password = False, snk_tool = None):
    """Runs the shared conversion for a `certificate_<format>` rule.

    Args:
        ctx: the rule context.
        fmt: sign_tool `--convert-format`.
        outputs: dict with a required `out` File and optional `cert_out` and
            `public_key_out` Files.
        out_password: whether the format is protected by an output password.
        snk_tool: the strong-name converter, for the `snk` format.
    """
    info = ctx.attr.certificate[SigningCertificateInfo]
    if info.certificate == None:
        fail("rules_signing: `{}` has no certificate material to convert.".format(ctx.attr.certificate.label))

    cosign_tool = None
    if fmt == "cosign":
        cosign_tool = _toolchain_tool(ctx, COSIGN_TOOLCHAIN)
        if cosign_tool == None:
            fail(
                "rules_signing: `{}` requires the cosign toolchain, ".format(ctx.label.name) +
                "which was not resolved. Register it with `signing_tools.cosign()` and " +
                "`register_toolchains(\"@signing_cosign//:cosign_toolchain\")`.",
            )

    convert_certificate(
        ctx,
        info = info,
        fmt = fmt,
        outputs = outputs,
        converter = ctx.executable._converter,
        openssl_tc = ctx.toolchains[OPENSSL_TOOLCHAIN],
        cosign_tool = cosign_tool,
        snk_tool = snk_tool,
        alias = getattr(ctx.attr, "alias", ""),
        out_password = ctx.attr.password if out_password else "",
        out_password_env = ctx.attr.password_env if out_password else "",
        stamp_defaults = ctx.attr.stamp_defaults,
    )

def _toolchain_tool(ctx, toolchain_type):
    tc = ctx.toolchains[toolchain_type]
    return tc.tool if tc != None and hasattr(tc, "tool") else None

def _certificate_pem_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".pem")
    cert_out = ctx.actions.declare_file(ctx.label.name + ".crt")
    _convert(ctx, "pem", {"out": out, "cert_out": cert_out})
    info = ctx.attr.certificate[SigningCertificateInfo]
    return [
        DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out])),
        OutputGroupInfo(certificate = depset([out]), certificate_only = depset([cert_out])),
        SigningCertificateInfo(
            certificate = out,
            ca_file = None,  # already embedded in the PEM
            password = "",
            password_env = "",
            identity = info.identity,
            stamp_defaults = info.stamp_defaults,
        ),
    ]

def _certificate_p12_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".p12")
    cert_out = ctx.actions.declare_file(ctx.label.name + ".crt")
    _convert(ctx, "p12", {"out": out, "cert_out": cert_out}, out_password = True)
    info = ctx.attr.certificate[SigningCertificateInfo]
    has_out_password = bool(ctx.attr.password or ctx.attr.password_env)
    return [
        DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out])),
        OutputGroupInfo(certificate = depset([out]), certificate_only = depset([cert_out])),
        SigningCertificateInfo(
            certificate = out,
            ca_file = None,  # already embedded in the PKCS#12
            password = ctx.attr.password if has_out_password else info.password,
            password_env = ctx.attr.password_env if has_out_password else info.password_env,
            identity = info.identity,
            stamp_defaults = dict(info.stamp_defaults, **ctx.attr.stamp_defaults),
        ),
    ]

def _certificate_keystore_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".keystore")
    _convert(ctx, "keystore", {"out": out}, out_password = True)
    return [DefaultInfo(files = depset([out]), runfiles = ctx.runfiles(files = [out]))]

def _certificate_snk_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".snk")
    public_out = ctx.actions.declare_file(ctx.label.name + ".public.snk")
    _convert(ctx, "snk", {"out": out, "public_key_out": public_out}, snk_tool = ctx.attr._snk_tool)
    return [
        DefaultInfo(files = depset([out, public_out]), runfiles = ctx.runfiles(files = [out, public_out])),
        OutputGroupInfo(key_pair = depset([out]), public_key = depset([public_out])),
    ]

def _certificate_keypair_impl(ctx):
    key_out = ctx.actions.declare_file(ctx.label.name + ".key")
    public_out = ctx.actions.declare_file(ctx.label.name + ".pub")
    cert_out = ctx.actions.declare_file(ctx.label.name + ".crt")
    _convert(
        ctx,
        "cosign",
        {"out": key_out, "public_key_out": public_out, "cert_out": cert_out},
        out_password = True,
    )
    files = [key_out, public_out, cert_out]
    return [
        DefaultInfo(files = depset(files), runfiles = ctx.runfiles(files = files)),
        OutputGroupInfo(
            private_key = depset([key_out]),
            public_key = depset([public_out]),
            certificate_only = depset([cert_out]),
        ),
    ]

_COMMON_ATTRS = dict({
    "certificate": attr.label(
        mandatory = True,
        providers = [SigningCertificateInfo],
        doc = "A `certificate` or `self_signed_certificate` target to convert.",
    ),
    "stamp_defaults": attr.string_dict(
        doc = "Extra fallback values for unresolved `{KEY}` placeholders.",
    ),
    "_converter": attr.label(
        default = "@rules_signing//signing/private/tools:sign_tool",
        executable = True,
        cfg = "exec",
    ),
}, **STAMP_ATTRS)

_PASSWORD_ATTRS = {
    "password": attr.string(
        doc = "Password protecting the output, with optional `{KEY}` stamp " +
              "placeholders. Defaults to the input certificate's password.",
    ),
    "password_env": attr.string(
        doc = "Environment variable holding the output password, used when " +
              "`password` is not set.",
    ),
}

_ALIAS_ATTR = {
    "alias": attr.string(
        default = "rules-signing",
        doc = "Alias (friendly name) of the key entry in the keystore.",
    ),
}

_TOOLCHAINS = [config_common.toolchain_type(OPENSSL_TOOLCHAIN, mandatory = False)]
_KEYPAIR_TOOLCHAINS = _TOOLCHAINS + [config_common.toolchain_type(COSIGN_TOOLCHAIN, mandatory = False)]

certificate_pem = rule(
    implementation = _certificate_pem_impl,
    doc = "Converts a certificate into a single unencrypted PEM file holding " +
          "the private key, the certificate and (if the input has a `ca_file`) " +
          "its issuing chain, plus the bare certificate as `<name>.crt`. " +
          "Provides `SigningCertificateInfo`, so it can feed `sign`. " +
          "Requires the openssl toolchain.",
    attrs = _COMMON_ATTRS,
    toolchains = _TOOLCHAINS,
    provides = [DefaultInfo, OutputGroupInfo, SigningCertificateInfo],
)

certificate_p12 = rule(
    implementation = _certificate_p12_impl,
    doc = "Converts a certificate into a PKCS#12 bundle (`<name>.p12`) " +
          "protected by `password`, plus the bare certificate as " +
          "`<name>.crt` (`certificate_only` output group). Provides `SigningCertificateInfo`. Requires the " +
          "openssl toolchain.",
    attrs = dict(_COMMON_ATTRS, **dict(_PASSWORD_ATTRS, **_ALIAS_ATTR)),
    toolchains = _TOOLCHAINS,
    provides = [DefaultInfo, OutputGroupInfo, SigningCertificateInfo],
)

certificate_keystore = rule(
    implementation = _certificate_keystore_impl,
    doc = "Converts a certificate into a PKCS#12 keystore (`<name>.keystore`) " +
          "with the key under `alias`, as consumed by `jarsigner`/`keytool` " +
          "(`-storetype PKCS12`). Requires the openssl toolchain.",
    attrs = dict(_COMMON_ATTRS, **dict(_PASSWORD_ATTRS, **_ALIAS_ATTR)),
    toolchains = _TOOLCHAINS,
)

certificate_snk = rule(
    implementation = _certificate_snk_impl,
    doc = "Converts a certificate's RSA key into .NET strong-name key files: " +
          "`<name>.snk` (the key pair) and `<name>.public.snk` (public key " +
          "only, for `PublicSign`/`DelaySign`). Only RSA keys are supported. " +
          "The key is converted by a small .NET program built with " +
          "rules_dotnet. Requires the openssl toolchain.",
    attrs = dict(_COMMON_ATTRS, **{
        "_snk_tool": attr.label(
            default = "@rules_signing//signing/private/tools/snk:snk_tool",
            executable = True,
            cfg = "exec",
        ),
    }),
    toolchains = _TOOLCHAINS,
)

certificate_keypair = rule(
    implementation = _certificate_keypair_impl,
    doc = "Splits a certificate into a cosign key pair -- `<name>.key` (cosign's " +
          "encrypted envelope, protected by `password`) and `<name>.pub` -- " +
          "plus the bare certificate as `<name>.crt`. Works directly with " +
          "`cosign sign-blob --key` / `cosign verify-blob --key`. For a plain " +
          "PEM key use `certificate_pem`. Requires the openssl and cosign " +
          "toolchains.",
    attrs = dict(_COMMON_ATTRS, **_PASSWORD_ATTRS),
    toolchains = _KEYPAIR_TOOLCHAINS,
)
