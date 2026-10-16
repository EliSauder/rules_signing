"""Rules that re-express a `certificate` in another file format."""

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load("//signing:providers.bzl", "SigningCertificateInfo")
load("//signing/private:action.bzl", "COSIGN_TOOLCHAIN", "OPENSSL_TOOLCHAIN")

def _needs_stamp(values):
    for v in values:
        if v and "{" in v:
            return True
    return False

def _convert(ctx, fmt, outputs, out_password = False, snk_tool = None):
    """Runs the `convert` mode of sign_tool.

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

    openssl_tc = ctx.toolchains[OPENSSL_TOOLCHAIN]
    openssl_file = openssl_tc.tool if openssl_tc != None and hasattr(openssl_tc, "tool") else None
    if openssl_file == None:
        fail(
            "rules_signing: `{}` requires the openssl toolchain, which was not resolved.\n".format(ctx.label.name) +
            "Register it with:\n" +
            "    signing_tools = use_extension(\"@rules_signing//signing:extensions.bzl\", \"signing_tools\")\n" +
            "    signing_tools.openssl(path = \"openssl\")\n" +
            "    use_repo(signing_tools, \"signing_openssl\")\n" +
            "    register_toolchains(\"@signing_openssl//:openssl_toolchain\")",
        )

    args = ctx.actions.args()

    # A parameter file keeps passwords out of process listings.
    args.set_param_file_format("multiline")
    args.use_param_file("--args-file=%s", use_always = True)

    args.add("--mode", "convert")
    args.add("--openssl-tool", openssl_file.path)
    args.add("--convert-format", fmt)
    args.add("--cert-file", info.certificate)
    args.add("--out", outputs["out"])
    if outputs.get("cert_out"):
        args.add("--cert-out", outputs["cert_out"])
    if outputs.get("public_key_out"):
        args.add("--public-key-out", outputs["public_key_out"])

    inputs = [info.certificate]
    if fmt == "cosign":
        cosign_tc = ctx.toolchains[COSIGN_TOOLCHAIN]
        cosign_file = cosign_tc.tool if cosign_tc != None and hasattr(cosign_tc, "tool") else None
        if cosign_file == None:
            fail(
                "rules_signing: `{}` requires the cosign toolchain, ".format(ctx.label.name) +
                "which was not resolved. Register it with `signing_tools.cosign()` and " +
                "`register_toolchains(\"@signing_cosign//:cosign_toolchain\")`.",
            )
        args.add("--cosign-tool", cosign_file.path)
        inputs.append(cosign_file)
    tools = [ctx.attr._converter[DefaultInfo].files_to_run]
    if snk_tool:
        args.add("--snk-tool", snk_tool[DefaultInfo].files_to_run.executable.path)
        tools.append(snk_tool[DefaultInfo].files_to_run)
    if info.ca_file:
        args.add("--ca-file", info.ca_file)
        inputs.append(info.ca_file)
    if info.password:
        args.add("--password-template", info.password)
    if info.password_env:
        args.add("--password-env", info.password_env)

    templates = [info.password]
    alias = getattr(ctx.attr, "alias", "")
    if alias:
        args.add("--alias", alias)
    if out_password:
        if ctx.attr.password:
            args.add("--out-password-template", ctx.attr.password)
        if ctx.attr.password_env:
            args.add("--out-password-env", ctx.attr.password_env)
        templates.append(ctx.attr.password)

    stamp_defaults = dict(info.stamp_defaults)
    stamp_defaults.update(ctx.attr.stamp_defaults)
    for k, v in stamp_defaults.items():
        args.add("--stamp-default", "{}={}".format(k, v))

    if _needs_stamp(templates):
        stamp = maybe_stamp(ctx)
        if stamp:
            args.add("--info-file", stamp.stable_status_file)
            args.add("--version-file", stamp.volatile_status_file)
            inputs.extend([stamp.stable_status_file, stamp.volatile_status_file])

    if hasattr(openssl_tc, "data"):
        inputs.extend(openssl_tc.data.to_list())
    else:
        inputs.append(openssl_file)

    ctx.actions.run(
        executable = ctx.executable._converter,
        tools = tools,
        arguments = [args],
        inputs = depset(inputs),
        outputs = [f for f in outputs.values() if f != None],
        mnemonic = "ConvertCertificate",
        progress_message = "Converting certificate to {} for {}".format(fmt, ctx.label),
    )

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
    if ctx.attr.snk_tool == None:
        fail(
            "rules_signing: `{}` needs `snk_tool`, a .NET binary built from ".format(ctx.label.name) +
            "@rules_signing//signing/private/tools:SnkTool.cs, e.g.\n" +
            "    csharp_binary(\n" +
            "        name = \"snk_tool\",\n" +
            "        srcs = [\"@rules_signing//signing/private/tools:SnkTool.cs\"],\n" +
            "        target_frameworks = [\"net9.0\"],\n" +
            "    )",
        )
    out = ctx.actions.declare_file(ctx.label.name + ".snk")
    public_out = ctx.actions.declare_file(ctx.label.name + ".public.snk")
    _convert(ctx, "snk", {"out": out, "public_key_out": public_out}, snk_tool = ctx.attr.snk_tool)
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
          "The key is converted by a small .NET program you build with " +
          "rules_dotnet (see `snk_tool`). Requires the openssl toolchain.",
    attrs = dict(_COMMON_ATTRS, **{
        "snk_tool": attr.label(
            executable = True,
            cfg = "exec",
            doc = "The strong-name converter, a .NET binary built from " +
                  "`@rules_signing//signing/private/tools:SnkTool.cs` with " +
                  "your own rules_dotnet. Kept out of rules_signing's own " +
                  "dependencies so consumers that do not use " +
                  "`certificate_snk` never need a .NET toolchain.",
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
