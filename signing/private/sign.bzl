load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
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

    # For cosign, require the toolchain only if at least one input would be
    # routed to cosign (unknown extensions) or requires runtime detection.

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

def _needs_toolchain_reason(srcs, selected_tool, tool_kind):
    """Explains why `tool_kind` was required, for the failure message.

    With an explicit `tool` the answer is trivial, but under `auto` the
    requirement usually comes from an input whose signer cannot be known until
    the action runs, which is otherwise a confusing thing to be asked to
    register a toolchain for.
    """
    if selected_tool == tool_kind:
        return "`tool = \"{}\"` was requested".format(tool_kind)

    for f in srcs:
        if f.is_directory:
            return (
                "`tool = \"auto\"` and '{}' is a directory artifact, whose ".format(f.short_path) +
                "contents are only known when the action runs, so every " +
                "signer must be available"
            )
        if not _has_known_extension(f):
            return (
                "`tool = \"auto\"` and '{}' has no recognizable ".format(f.short_path) +
                "extension, so it is classified by its header bytes at " +
                "execution time and every signer must be available"
            )

    return "`tool = \"auto\"` and at least one input is signed with it"

def _fail_missing_toolchain(tool_kind, registration, reason, selected_tool):
    hint = ""
    if selected_tool == "auto":
        hint = (
            "\nAlternatively, set `tool` on this target to name the single " +
            "signer you need, which requests no other toolchain."
        )
    fail(
        "rules_signing: the {} toolchain is required but was not resolved.\n".format(tool_kind) +
        "Required because {}.\n".format(reason) +
        "Register it with:\n    register_toolchains({})".format(registration) +
        hint,
    )

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
        _fail_missing_toolchain(
            "osslsigncode",
            "\"@signing_osslsigncode//:osslsigncode_toolchain\"",
            _needs_toolchain_reason(srcs, ctx.attr.tool, "osslsigncode"),
            ctx.attr.tool,
        )
    osslsigncode_tool = osslsigncode_tc.tool.path if osslsigncode_tc and hasattr(osslsigncode_tc, "tool") else ""
    args.add("--osslsigncode-tool", osslsigncode_tool)

    # Get cosign toolchain details
    cosign_tc = ctx.toolchains[_COSIGN_TOOLCHAIN]
    needs_cosign = _needs_toolchain(srcs, ctx.attr.tool, "cosign")
    if needs_cosign and (cosign_tc == None or not hasattr(cosign_tc, "tool")):
        _fail_missing_toolchain(
            "cosign",
            "\"@signing_cosign//:cosign_toolchain\"",
            _needs_toolchain_reason(srcs, ctx.attr.tool, "cosign"),
            ctx.attr.tool,
        )
    cosign_tool = cosign_tc.tool.path if cosign_tc and hasattr(cosign_tc, "tool") else ""
    args.add("--cosign-tool", cosign_tool)

    # Get codesign toolchain details
    codesign_tc = ctx.toolchains[_CODESIGN_TOOLCHAIN]
    needs_codesign = _needs_toolchain(srcs, ctx.attr.tool, "codesign")
    if needs_codesign and codesign_tc == None:
        _fail_missing_toolchain(
            "codesign",
            "\"@codesign.bzl//toolchain:all\"",
            _needs_toolchain_reason(srcs, ctx.attr.tool, "codesign"),
            ctx.attr.tool,
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

    # Passing each (relpath, src) pair as separate --rel/--src argv tokens
    # would round-trip file names through the OS's native command-line
    # encoding. On Windows that's the system's ANSI code page, not UTF-8, so
    # any relpath character outside it (e.g. non-Latin scripts) arrives at
    # sign_tool corrupted. Writing the pairs to a manifest file instead keeps
    # them as file content, which Bazel always writes and Python always reads
    # as UTF-8, sidestepping the OS argv encoding entirely.
    flatten_single_directory = len(srcs) == 1 and srcs[0].is_directory
    manifest_lines = []
    for f in srcs:
        relpath = "" if flatten_single_directory and f.is_directory else f.short_path
        manifest_lines.append("{}\t{}".format(relpath, f.path))
    rel_src_manifest = ctx.actions.declare_file(ctx.label.name + ".rel_src_manifest")
    ctx.actions.write(rel_src_manifest, "".join([line + "\n" for line in manifest_lines]))
    args.add("--rel-src-manifest", rel_src_manifest.path)

    stamp = maybe_stamp(ctx)
    extra_inputs = add_cert_args(args, cert, stamp)
    inputs = srcs + extra_inputs + [rel_src_manifest]
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
        # `data` includes the tool itself plus any files it needs alongside
        # it at runtime (e.g. Windows' libcrypto/libssl DLLs); adding them
        # all as plain action inputs stages them in the sandbox next to
        # openssl.exe, which is what its same-directory DLL search needs.
        if openssl_tc != None and hasattr(openssl_tc, "data"):
            inputs.extend(openssl_tc.data.to_list())
        else:
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
    attrs = dict({
        "src": attr.label(
            mandatory = True,
            providers = [[DefaultInfo]],
            cfg = "target",
        ),
        "out": attr.string(doc = "Optional output directory artifact name."),
        "tool": attr.string(
            default = "auto",
            values = ["osslsigncode", "codesign", "cosign", "auto"],
            doc = "Which signer to use, or \"auto\" (the default) to select " +
                  "one per file from its extension and, failing that, its " +
                  "header bytes. Note that \"auto\" requires every signing " +
                  "toolchain to be registered whenever an input is a " +
                  "directory artifact or has no recognizable extension, " +
                  "because the contents that decide the signer are not " +
                  "known until the action runs. Naming a single tool " +
                  "explicitly requests only that toolchain.",
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
    }, **STAMP_ATTRS),
    toolchains = [
        config_common.toolchain_type(_OSSLSIGNCODE_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_COSIGN_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_CODESIGN_TOOLCHAIN, mandatory = False),
        config_common.toolchain_type(_OPENSSL_TOOLCHAIN, mandatory = False),
    ],
)
