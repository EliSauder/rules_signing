load(
    "//signing/private:common.bzl",
    "add_cert_args",
    "cert_info",
)
load("//signing:providers.bzl", "SigningCertificateInfo")

_OSSLSIGNCODE_TOOLCHAIN = "//signing/toolchains:osslsigncode_toolchain_type"
_COSIGN_TOOLCHAIN = "//signing/toolchains:cosign_toolchain_type"
_CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"
_OPENSSL_TOOLCHAIN = "//signing/toolchains:openssl_toolchain_type"

_OSSLSIGNCODE_EXT = [
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".cat",
    ".ocx",
    ".efi",
    ".appx",
    ".cab",
    ".ps1",
    ".ps1xml",
    ".psc1",
    ".psd1",
    ".psm1",
    ".cdxml",
    ".mof",
    ".js",
]

_CODESIGN_EXT = [
    ".app",
    ".pkg",
    ".dmg",
]

def _detect_tool(src):
    p = src.short_path.lower()
    for ext in _OSSLSIGNCODE_EXT:
        if p.endswith(ext):
            return "osslsigncode"
    for ext in _CODESIGN_EXT:
        if p.endswith(ext):
            return "codesign"
    return "cosign"

def _has_known_extension(src):
    p = src.short_path.lower()
    for ext in _OSSLSIGNCODE_EXT + _CODESIGN_EXT:
        if p.endswith(ext):
            return True

    # A basename with no dot cannot be classified by extension at all.
    basename = p.rpartition("/")[2]
    return "." in basename

def _needs_toolchain(srcs, selected_tool, tool_kind):
    if selected_tool == tool_kind:
        return True
    if selected_tool != "auto":
        return False

    # cosign is the universal fallback in auto mode: anything without a native
    # signer is signed with a detached cosign signature, so it must always be
    # present.
    if tool_kind == "cosign":
        return True

    for f in srcs:
        # Directory artifact contents are only available at execution time, so
        # require every native signer: an ordinary directory may hold nested
        # exe/dll files needing osslsigncode, or Mach-O binaries and nested
        # .app/.dmg/.pkg bundles needing codesign.
        if f.is_directory:
            return True

        # Extensionless files are classified by sniffing their header at
        # execution time, which analysis cannot do, so both native signers must
        # be available. This is common for Mach-O binaries on macOS.
        if not _has_known_extension(f):
            return True

        if _detect_tool(f) == tool_kind:
            return True
    return False

def _codesign_tool_file(codesign_tc):
    """Returns the codesign executable File from the codesign.bzl toolchain.

    codesign.bzl exposes ToolchainInfo(codesign = <File>) directly
    """
    if codesign_tc == None:
        return None
    return codesign_tc.codesign

def _sign_impl(ctx):
    srcs = ctx.attr.src[DefaultInfo].files.to_list()
    out_name = ctx.attr.out if ctx.attr.out else "{}.signed".format(ctx.label.name)
    out_dir = ctx.actions.declare_directory(out_name)
    cert = cert_info(ctx)

    args = ctx.actions.args()
    args.add("--out-dir", out_dir.path)
    args.add("--tool", ctx.attr.tool)

    # Get osslsigncode toolchain details
    osslsigncode_tc = ctx.toolchains[_OSSLSIGNCODE_TOOLCHAIN]
    needs_osslsigncode = _needs_toolchain(srcs, ctx.attr.tool, "osslsigncode")
    if needs_osslsigncode and (osslsigncode_tc == None or not hasattr(osslsigncode_tc, "tool")):
        fail("osslsigncode toolchain is required but was not resolved")
    osslsigncode_tool = osslsigncode_tc.tool.path if osslsigncode_tc and hasattr(osslsigncode_tc, "tool") else ""
    args.add("--osslsigncode-tool", osslsigncode_tool)

    # Get cosign toolchain details
    cosign_tc = ctx.toolchains[_COSIGN_TOOLCHAIN]
    needs_cosign = _needs_toolchain(srcs, ctx.attr.tool, "cosign")
    if needs_cosign and (cosign_tc == None or not hasattr(cosign_tc, "tool")):
        fail("cosign toolchain is required but was not resolved")
    cosign_tool = cosign_tc.tool.path if cosign_tc and hasattr(cosign_tc, "tool") else ""
    args.add("--cosign-tool", cosign_tool)

    # Get codesign toolchain details
    codesign_tc = ctx.toolchains[_CODESIGN_TOOLCHAIN]
    needs_codesign = _needs_toolchain(srcs, ctx.attr.tool, "codesign")
    if needs_codesign and codesign_tc == None:
        fail(
            "codesign toolchain is required but was not resolved; register it with " +
            "register_toolchains(\"@codesign.bzl//toolchain:all\")",
        )
    codesign_file = _codesign_tool_file(codesign_tc)
    codesign_tool = codesign_file.path if codesign_file else ""
    if needs_codesign and not codesign_tool:
        fail("codesign toolchain is resolved but does not expose an executable tool")
    args.add("--codesign-tool", codesign_tool)

    # openssl is optional and only consulted when PKCS#12 material has to be
    # converted to PEM for cosign, which cannot be known until the action runs.
    # It is therefore never required at analysis time; sign_tool raises an
    # actionable error if the conversion turns out to be necessary.
    openssl_tc = ctx.toolchains[_OPENSSL_TOOLCHAIN]
    openssl_file = openssl_tc.tool if openssl_tc != None and hasattr(openssl_tc, "tool") else None
    if openssl_file:
        args.add("--openssl-tool", openssl_file.path)

    # Handle other args
    if ctx.attr.timestamp_url:
        args.add("--timestamp-url", ctx.attr.timestamp_url)
    if ctx.attr.transparency_log:
        args.add("--transparency-log", ctx.attr.transparency_log)
    if ctx.attr.description:
        args.add("--name", ctx.attr.description)
    if ctx.attr.url:
        args.add("--url", ctx.attr.url)
    if ctx.attr.options:
        args.add("--options", ",".join(ctx.attr.options))
    if ctx.file.entitlements:
        args.add("--entitlements", ctx.file.entitlements.path)

    flatten_single_directory = len(srcs) == 1 and srcs[0].is_directory
    for f in srcs:
        relpath = "" if flatten_single_directory and f.is_directory else f.short_path
        args.add("--rel", relpath)
        args.add("--src", f.path)

    extra_inputs = add_cert_args(ctx, args, cert)
    inputs = srcs + extra_inputs
    tools = [ctx.executable._tool]
    if ctx.file.entitlements:
        inputs.append(ctx.file.entitlements)

    # Add toolchain inputs
    if osslsigncode_tc != None and hasattr(osslsigncode_tc, "tool"):
        inputs.append(osslsigncode_tc.tool)
    if cosign_tc != None and hasattr(cosign_tc, "tool"):
        inputs.append(cosign_tc.tool)
    if codesign_file:
        inputs.append(codesign_file)
    if openssl_file:
        inputs.append(openssl_file)

    ctx.actions.run(
        executable = ctx.executable._tool,
        inputs = depset(inputs),
        tools = tools,
        outputs = [out_dir],
        arguments = [args],
        mnemonic = "SignTree",
        progress_message = "Signing output tree for {}".format(ctx.label),
    )

    return [DefaultInfo(
        files = depset([out_dir]),
        runfiles = ctx.attr.src[DefaultInfo].default_runfiles.merge(ctx.runfiles(files = [out_dir])),
    )]

sign = rule(
    implementation = _sign_impl,
    doc = "Signs all files from `src`, preserving relative output structure.",
    attrs = {
        "src": attr.label(
            mandatory = True,
            providers = [[DefaultInfo]],
            cfg = "target",
        ),
        "out": attr.string(doc = "Optional output directory artifact name."),
        "tool": attr.string(
            default = "auto",
            values = ["osslsigncode", "codesign", "cosign", "auto"],
        ),
        "certificate": attr.label(
            providers = [[SigningCertificateInfo]],
        ),
        "timestamp_url": attr.string(
            default = "",
            doc = "Timestamp authority to countersign with. Empty (the " +
                  "default) does not timestamp, so signing makes no network " +
                  "call and no third party is told when you build. Set to " +
                  "\"default\" for the well-known authority of the signer in " +
                  "use (Apple's for codesign, DigiCert's for osslsigncode), " +
                  "or to the URL of a specific server. Note that without a " +
                  "timestamp a signature stops validating once the signing " +
                  "certificate expires, so released artifacts usually want " +
                  "one. Ignored by cosign.",
        ),
        "transparency_log": attr.string(
            default = "",
            doc = "Rekor transparency log to publish cosign signatures to. " +
                  "Empty (the default) publishes nothing, so signing stays " +
                  "offline and no hash of your build output leaves the " +
                  "machine. Set to \"default\" to opt in to the public " +
                  "Sigstore instance, or to the URL of a specific instance " +
                  "(such as a private Rekor deployment). Enabling this makes " +
                  "every signing action a network call.",
        ),
        "description": attr.string(doc = "Signature description when supported."),
        "url": attr.string(doc = "Publisher URL when supported."),
        "options": attr.string_list(
            default = ["runtime"],
            doc = "codesign --options values.",
        ),
        "entitlements": attr.label(allow_single_file = True),
        "_tool": attr.label(
            default = "@rules_signing//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = [
        config_common.toolchain_type(_OSSLSIGNCODE_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_COSIGN_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_CODESIGN_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_OPENSSL_TOOLCHAIN, mandatory = False),
    ],
)
