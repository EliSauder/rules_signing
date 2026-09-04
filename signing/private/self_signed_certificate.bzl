"""A `certificate` that issues its own throwaway signing material."""

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load("//signing:providers.bzl", "SigningCertificateInfo")
load("//signing/private:action.bzl", "OPENSSL_TOOLCHAIN")

_DIGESTS = ["sha256", "sha384", "sha512"]

def _needs_stamp(values):
    for v in values:
        if v and "{" in v:
            return True
    return False

def _self_signed_certificate_impl(ctx):
    openssl_tc = ctx.toolchains[OPENSSL_TOOLCHAIN]
    openssl_file = openssl_tc.tool if openssl_tc != None and hasattr(openssl_tc, "tool") else None
    if openssl_file == None:
        # Unlike signing, where openssl is only consulted for a conversion
        # that may never happen, issuing a certificate cannot proceed without
        # it at all -- so it is reported during analysis rather than part-way
        # through the action.
        fail(
            "rules_signing: `self_signed_certificate` requires the openssl " +
            "toolchain, which was not resolved.\nRegister it with:\n" +
            "    signing_tools = use_extension(\"@rules_signing//signing:extensions.bzl\", \"signing_tools\")\n" +
            "    signing_tools.openssl(path = \"openssl\")\n" +
            "    use_repo(signing_tools, \"signing_openssl\")\n" +
            "    register_toolchains(\"@signing_openssl//:openssl_toolchain\")",
        )

    if ctx.attr.key_type == "rsa" and ctx.attr.key_size < 2048:
        fail(
            "rules_signing: `key_size` of {} is too small to be accepted by ".format(ctx.attr.key_size) +
            "signers and verifiers; use 2048 or more.",
        )
    if ctx.attr.validity_days < 1:
        fail("rules_signing: `validity_days` must be at least 1.")

    common_name = ctx.attr.common_name if ctx.attr.common_name else ctx.label.name

    material = ctx.actions.declare_file("{}.{}".format(ctx.label.name, ctx.attr.format))
    cert_out = ctx.actions.declare_file("{}.crt".format(ctx.label.name))
    public_key_out = ctx.actions.declare_file("{}.pub".format(ctx.label.name))

    args = ctx.actions.args()

    # Everything is passed through a parameter file so the password never
    # appears in a process listing, matching how `sign` passes its own
    # arguments.
    args.set_param_file_format("multiline")
    args.use_param_file("--args-file=%s", use_always = True)

    args.add("--mode", "gen-self-signed")
    args.add("--openssl-tool", openssl_file.path)
    args.add("--out", material)
    args.add("--cert-out", cert_out)
    args.add("--public-key-out", public_key_out)
    args.add("--format", ctx.attr.format)
    args.add("--key-type", ctx.attr.key_type)
    args.add("--key-size", str(ctx.attr.key_size))
    args.add("--ec-curve", ctx.attr.ec_curve)
    args.add("--digest", ctx.attr.digest)
    args.add("--validity-days", str(ctx.attr.validity_days))
    args.add("--common-name", common_name)

    # Empty arguments are dropped when the parameter file is read back (a
    # blank line carries no argument), so optional fields are only added when
    # they have a value.
    for flag, value in [
        ("--organization", ctx.attr.organization),
        ("--organizational-unit", ctx.attr.organizational_unit),
        ("--country", ctx.attr.country),
        ("--state", ctx.attr.state),
        ("--locality", ctx.attr.locality),
        ("--email", ctx.attr.email),
    ]:
        if value:
            args.add(flag, value)
    args.add_all(ctx.attr.subject_alt_names, before_each = "--subject-alt-name")
    args.add_all(ctx.attr.key_usages, before_each = "--key-usage")
    args.add_all(ctx.attr.extended_key_usages, before_each = "--extended-key-usage")
    if ctx.attr.password:
        args.add("--password-template", ctx.attr.password)
    if ctx.attr.password_env:
        args.add("--password-env", ctx.attr.password_env)
    for k, v in ctx.attr.stamp_defaults.items():
        args.add("--stamp-default", "{}={}".format(k, v))

    inputs = []
    if hasattr(openssl_tc, "data"):
        # Windows' openssl.exe loads libcrypto/libssl from its own directory,
        # so whatever the toolchain ships alongside the binary is staged too.
        inputs.extend(openssl_tc.data.to_list())
    else:
        inputs.append(openssl_file)

    if _needs_stamp([ctx.attr.common_name, ctx.attr.organization, ctx.attr.password]):
        stamp = maybe_stamp(ctx)
        if stamp:
            args.add("--info-file", stamp.stable_status_file)
            args.add("--version-file", stamp.volatile_status_file)
            inputs.extend([stamp.stable_status_file, stamp.volatile_status_file])

    ctx.actions.run(
        executable = ctx.executable._generator,
        arguments = [args],
        inputs = depset(inputs),
        outputs = [material, cert_out, public_key_out],
        mnemonic = "GenSelfSignedCertificate",
        progress_message = "Generating self-signed certificate for {}".format(ctx.label),
        # The private key is generated fresh, so it must not be uploaded to a
        # cache other machines can read. A local cache still keeps the key
        # stable for the lifetime of the output tree, which is what stops
        # every build from re-issuing (and thus invalidating) it.
        execution_requirements = {
            "no-remote-cache": "1",
            "no-remote-cache-upload": "1",
        },
    )

    files = [material, cert_out, public_key_out]
    return [
        DefaultInfo(
            files = depset(files),
            runfiles = ctx.runfiles(files = files),
        ),
        OutputGroupInfo(
            certificate = depset([material]),
            certificate_only = depset([cert_out]),
            public_key = depset([public_key_out]),
        ),
        SigningCertificateInfo(
            certificate = material,
            # Self-signed means the certificate is its own issuer, so there is
            # no intermediate chain to embed in the signature.
            ca_file = None,
            password = ctx.attr.password if ctx.attr.format == "p12" else "",
            password_env = ctx.attr.password_env if ctx.attr.format == "p12" else "",
            identity = ctx.attr.identity,
            stamp_defaults = ctx.attr.stamp_defaults,
        ),
    ]

self_signed_certificate = rule(
    implementation = _self_signed_certificate_impl,
    doc = "Issues a self-signed code-signing certificate during the build and " +
          "provides it as `SigningCertificateInfo`, so it can be handed to " +
          "`sign` (or any rule using `//signing:actions.bzl`) wherever a " +
          "`certificate` target is accepted.\n\n" +
          "Nothing trusts a certificate that signs itself, so this is for " +
          "development, tests and internal artifacts -- it makes a signed " +
          "build reproducible for contributors who have no key, without " +
          "checking a private key into the repository. Releases still need a " +
          "real certificate supplied through `certificate`.\n\n" +
          "Requires the openssl toolchain. Three files are produced: the " +
          "signing material (a unified PEM holding the private key and the " +
          "certificate, or a PKCS#12 bundle when `format = \"p12\"`), the " +
          "bare certificate as `<name>.crt` for use as a verification trust " +
          "anchor, and its public key as `<name>.pub` for verifying cosign " +
          "signatures.",
    attrs = dict({
        "common_name": attr.string(
            doc = "Certificate subject common name (CN). Defaults to the " +
                  "target name. Supports `{KEY}` stamp placeholders.",
        ),
        "organization": attr.string(
            doc = "Subject organization (O). Supports `{KEY}` stamp placeholders.",
        ),
        "organizational_unit": attr.string(doc = "Subject organizational unit (OU)."),
        "country": attr.string(doc = "Subject two-letter country code (C)."),
        "state": attr.string(doc = "Subject state or province (ST)."),
        "locality": attr.string(doc = "Subject locality (L)."),
        "email": attr.string(doc = "Subject email address."),
        "subject_alt_names": attr.string_list(
            doc = "Subject alternative names, each written in openssl's own " +
                  "form, for example `DNS:example.com` or " +
                  "`email:dev@example.com`.",
        ),
        "validity_days": attr.int(
            default = 365,
            doc = "How long the certificate stays valid, in days. Note that " +
                  "signatures made without a timestamp stop verifying once " +
                  "the certificate expires.",
        ),
        "key_type": attr.string(
            default = "rsa",
            values = ["rsa", "ec"],
            doc = "Key algorithm. Both RSA and EC are accepted by every signer.",
        ),
        "key_size": attr.int(
            default = 2048,
            doc = "RSA key size in bits. Ignored for `key_type = \"ec\"`.",
        ),
        "ec_curve": attr.string(
            default = "prime256v1",
            doc = "EC curve name. Ignored for `key_type = \"rsa\"`.",
        ),
        "digest": attr.string(
            default = "sha256",
            values = _DIGESTS,
            doc = "Digest used for the certificate's own signature.",
        ),
        "format": attr.string(
            default = "pem",
            values = ["pem", "p12"],
            doc = "Shape of the generated signing material. `pem` (the " +
                  "default) writes the private key and certificate into one " +
                  "unencrypted file, which every signer reads directly. " +
                  "`p12` writes a PKCS#12 bundle protected by `password`; " +
                  "cosign then needs the openssl toolchain to convert it, " +
                  "which this rule already requires.",
        ),
        "password": attr.string(
            doc = "Password protecting the PKCS#12 bundle when " +
                  "`format = \"p12\"`. Supports `{KEY}` stamp placeholders. " +
                  "Ignored for `format = \"pem\"`, whose private key is " +
                  "written unencrypted because the signers cannot decrypt it.",
        ),
        "password_env": attr.string(
            doc = "Name of an environment variable holding the PKCS#12 " +
                  "password, used when `password` is not set. The variable " +
                  "must reach the action (for example with `--action_env`).",
        ),
        "identity": attr.string(
            doc = "Optional Apple codesign identity template passed through " +
                  "to consumers, with `{KEY}` placeholders.",
        ),
        "key_usages": attr.string_list(
            default = ["digitalSignature"],
            doc = "X.509 keyUsage values, marked critical.",
        ),
        "extended_key_usages": attr.string_list(
            default = ["codeSigning"],
            doc = "X.509 extendedKeyUsage values. `codeSigning` alone is what " +
                  "every signer expects; Apple-specific critical extensions " +
                  "are deliberately not added, since osslsigncode rejects them.",
        ),
        "stamp_defaults": attr.string_dict(
            doc = "Fallback map for unresolved `{KEY}` placeholders.",
        ),
        "_generator": attr.label(
            default = "@rules_signing//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    }, **STAMP_ATTRS),
    toolchains = [
        config_common.toolchain_type(OPENSSL_TOOLCHAIN, mandatory = False),
    ],
    provides = [SigningCertificateInfo],
)
