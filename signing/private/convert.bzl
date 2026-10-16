"""The certificate conversion action shared by the format rules and signing.

The `certificate_<format>` rules expose a conversion as a target, while
`signing_context` runs the same conversion for the signers that only read one
specific format (cosign and jarsigner). Both go through `convert_certificate`
so a signer receives exactly what the matching format rule would produce.
"""

load("@bazel_lib//lib:stamping.bzl", "maybe_stamp")

OPENSSL_MISSING = (
    "Register it with:\n" +
    "    signing_tools = use_extension(\"@rules_signing//signing:extensions.bzl\", \"signing_tools\")\n" +
    "    signing_tools.openssl(path = \"openssl\")\n" +
    "    use_repo(signing_tools, \"signing_openssl\")\n" +
    "    register_toolchains(\"@signing_openssl//:openssl_toolchain\")"
)

def _needs_stamp(values):
    for v in values:
        if v and "{" in v:
            return True
    return False

def convert_certificate(
        ctx,
        *,
        info,
        fmt,
        outputs,
        converter,
        openssl_tc = None,
        cosign_tool = None,
        snk_tool = None,
        alias = "",
        out_password = "",
        out_password_env = "",
        stamp_defaults = {},
        optional = False):
    """Converts certificate material into another format with sign_tool.

    The conversion is never cached: its output holds a private key, which
    must not end up in a disk or remote cache.

    Args:
        ctx: the rule context. Its `stamp` attributes decide whether
            password templates can be stamped.
        info: the `SigningCertificateInfo` to convert. Its `certificate` must
            be set.
        fmt: sign_tool `--convert-format`.
        outputs: dict with a required `out` File and optional `cert_out` and
            `public_key_out` Files.
        converter: the sign_tool executable `File`.
        openssl_tc: the resolved openssl toolchain, or None. Every format but
            `cosign` needs it.
        cosign_tool: the cosign executable `File`, for the `cosign` format.
        snk_tool: the strong-name converter target, for the `snk` format.
        alias: the key alias for `p12`/`keystore`.
        out_password: password template protecting the output. Defaults to
            the input password.
        out_password_env: environment variable holding the output password.
        stamp_defaults: values for stamp keys missing from the build's stamp
            files, on top of the certificate's own.
        optional: leave the outputs empty instead of failing when the
            material cannot be converted (no material, or PKCS#12 converted
            to `cosign` without openssl), for a consumer that reports the
            error itself once it actually needs the output.
    """
    openssl_file = openssl_tc.tool if openssl_tc != None and hasattr(openssl_tc, "tool") else None
    if openssl_file == None and fmt != "cosign":
        fail(
            "rules_signing: `{}` requires the openssl toolchain, which was not resolved.\n".format(ctx.label.name) +
            OPENSSL_MISSING,
        )

    args = ctx.actions.args()

    # A parameter file keeps passwords out of process listings.
    args.set_param_file_format("multiline")
    args.use_param_file("--args-file=%s", use_always = True)

    args.add("--mode", "convert")
    args.add("--convert-format", fmt)
    args.add("--cert-file", info.certificate)
    args.add("--out", outputs["out"])
    if outputs.get("cert_out"):
        args.add("--cert-out", outputs["cert_out"])
    if outputs.get("public_key_out"):
        args.add("--public-key-out", outputs["public_key_out"])
    if optional:
        args.add("--convert-optional")

    inputs = [info.certificate]
    tools = [converter]
    if openssl_file:
        args.add("--openssl-tool", openssl_file.path)

        # `data` also carries the DLLs openssl.exe loads from its own
        # directory on Windows.
        if hasattr(openssl_tc, "data"):
            inputs.extend(openssl_tc.data.to_list())
        else:
            inputs.append(openssl_file)
    if fmt == "cosign":
        args.add("--cosign-tool", cosign_tool.path)
        inputs.append(cosign_tool)
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
    if alias:
        args.add("--alias", alias)
    if out_password:
        args.add("--out-password-template", out_password)
    if out_password_env:
        args.add("--out-password-env", out_password_env)

    defaults = dict(info.stamp_defaults)
    defaults.update(stamp_defaults)
    for k, v in defaults.items():
        args.add("--stamp-default", "{}={}".format(k, v))

    if _needs_stamp([info.password, out_password]):
        stamp = maybe_stamp(ctx)
        if stamp:
            args.add("--info-file", stamp.stable_status_file)
            args.add("--version-file", stamp.volatile_status_file)
            inputs.extend([stamp.stable_status_file, stamp.volatile_status_file])

    ctx.actions.run(
        executable = converter,
        tools = tools,
        arguments = [args],
        inputs = depset(inputs),
        outputs = [f for f in outputs.values() if f != None],
        mnemonic = "ConvertCertificate",
        progress_message = "Converting certificate to {} for {}".format(fmt, ctx.label),
        execution_requirements = {
            "no-cache": "1",
            "no-remote-cache": "1",
            "no-remote-cache-upload": "1",
        },
    )
