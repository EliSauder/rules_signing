"""Reusable building blocks for invoking the signer from any rule.

`sign` is only one way to use rules_signing. A rule that produces a signable
artifact of its own -- an installer, an archive, a bundle -- generally needs
the same certificate handling, toolchain resolution and diagnostics without
wanting `sign`'s "directory of signed copies" shape. Some cannot even use a
separate action: NSIS, for example, signs its uninstaller through the
`!uninstfinalize` compile-time hook, which hands a signer a path and expects
the file to come back signed, so the signer has to run *inside* the NSIS
compile action rather than after it.

Everything such a rule needs is exposed here:

* `SIGNING_ATTRS` and `SIGNING_TOOLCHAINS` to declare on the rule,
* `signing_context()` to resolve them into a ready-to-use signer,
* `signing_argv()` to build a command line for the resolved signer, and
* `sign_action()` for the common case of "sign these files into a directory".
"""

load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS", "maybe_stamp")
load(
    "//signing/private:common.bzl",
    "add_cert_args",
    "cert_info",
)
load("//signing:providers.bzl", "SigningCertificateInfo")

OSSLSIGNCODE_TOOLCHAIN = "//signing/toolchains:osslsigncode_toolchain_type"
COSIGN_TOOLCHAIN = "//signing/toolchains:cosign_toolchain_type"
CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"
OPENSSL_TOOLCHAIN = "//signing/toolchains:openssl_toolchain_type"

TOOL_KINDS = ["osslsigncode", "codesign", "cosign"]

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

_REGISTRATION = {
    "osslsigncode": "\"@signing_osslsigncode//:osslsigncode_toolchain\"",
    "cosign": "\"@signing_cosign//:cosign_toolchain\"",
    "codesign": "\"@codesign.bzl//toolchain:all\"",
}

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

def _needs_toolchain(srcs, selected_tool, tool_kind, require):
    if tool_kind in require:
        return True
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

def _needs_toolchain_reason(srcs, selected_tool, tool_kind, require, require_reason):
    """Explains why `tool_kind` was required, for the failure message.

    With an explicit `tool` the answer is trivial, but under `auto` the
    requirement usually comes from an input whose signer cannot be known until
    the action runs, which is otherwise a confusing thing to be asked to
    register a toolchain for.
    """
    if tool_kind in require:
        if require_reason:
            return require_reason
        return "this rule always signs with {}".format(tool_kind)
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

def _fail_missing_toolchain(tool_kind, reason, selected_tool):
    hint = ""
    if selected_tool == "auto":
        hint = (
            "\nAlternatively, set `tool` on this target to name the single " +
            "signer you need, which requests no other toolchain."
        )
    fail(
        "rules_signing: the {} toolchain is required but was not resolved.\n".format(tool_kind) +
        "Required because {}.\n".format(reason) +
        "Register it with:\n    register_toolchains({})".format(_REGISTRATION[tool_kind]) +
        hint,
    )

def _toolchain_tool(ctx, toolchain_type):
    """Returns the executable File a signing toolchain exposes, or None.

    `codesign.bzl` puts the executable on a `codesign` field while the
    toolchains generated by this module use `tool`, so both spellings are
    accepted rather than special-casing the caller.
    """
    tc = ctx.toolchains[toolchain_type]
    if tc == None:
        return None
    for field in ["tool", "codesign"]:
        f = getattr(tc, field, None)
        if f != None:
            return f
    return None

def signing_context(
        ctx,
        srcs = [],
        require = [],
        require_reason = "",
        tool = None,
        name = None,
        attr_prefix = "signing_"):
    """Resolves signing toolchains and certificate material for `ctx`.

    The rule calling this must have merged `SIGNING_ATTRS` into its `attrs`
    and `SIGNING_TOOLCHAINS` into its `toolchains`.

    Args:
        ctx: the rule context.
        srcs: Files that will be signed, when they are known at analysis time.
            Used only to work out which signing toolchains are required under
            `tool = "auto"`, and to explain why if one is missing. Rules that
            sign something produced by the action itself (so nothing is known
            yet) pass nothing here and use `require` instead.
        require: tool kinds (`"osslsigncode"`, `"codesign"`, `"cosign"`) that
            this rule always needs regardless of `srcs`. Use this when the
            signing target does not exist at analysis time, so that a missing
            toolchain fails during analysis with a clear message rather than
            part-way through the action.
        require_reason: human-readable explanation of `require`, quoted in the
            missing-toolchain error. For example "an NSIS uninstaller is
            always a PE executable".
        tool: overrides the `tool` attribute. Rules that only ever produce one
            kind of artifact can pin the signer here instead of exposing the
            choice.
        name: base name for the generated parameter file. Defaults to the
            target name. Pass distinct values if one target builds more than
            one signing context.
        attr_prefix: the prefix the signing attributes were declared with.
            Must match what was passed to `signing_attrs`.

    Returns:
        A struct with:

        * `executable`: the signer `File` to run.
        * `params_file`: a `File` holding every argument that does not name an
          input or output, meant to be passed as `@<path>`. Keeping them in a
          file rather than on the command line means certificate paths and
          passwords are not exposed in process listings or embedded into
          generated scripts, and are not subject to a third-party tool's
          quoting rules.
        * `inputs`: a `depset` of Files the action must declare as inputs.
        * `tools`: a list of Files for the action's `tools`.
        * `env`: environment variables needed when the signer is *not* the
          action's own executable (for example when another tool spawns it).
          Merge these into that action's `env`.
        * `required_env_vars`: names of environment variables the signer reads
          from the ambient environment (currently the certificate's
          `password_env`, if set). The caller must make sure these reach the
          action, typically with `--action_env`.
        * `tool_mode`: the resolved value of `tool`.
    """
    def attr(name):
        full = attr_prefix + name
        if not hasattr(ctx.attr, full):
            fail(
                "rules_signing: this rule has no `{}` attribute. ".format(full) +
                "Merge `signing_attrs(prefix = {})` into the rule's ".format(repr(attr_prefix)) +
                "`attrs`, or pass the matching `attr_prefix` to " +
                "`signing_context`.",
            )
        return getattr(ctx.attr, full)

    # `maybe_stamp` reads `stamp`/`_stamp_flag` with a default, so a rule that
    # forgot them would not fail -- it would quietly never stamp, and an
    # unresolved `{KEY}` in a password or identity template would surface much
    # later as a confusing signing error. Check for them up front instead.
    for stamp_attr in ["stamp", "_stamp_flag"]:
        if not hasattr(ctx.attr, stamp_attr):
            fail(
                "rules_signing: this rule is missing the `{}` attribute, ".format(stamp_attr) +
                "which the signer needs to resolve `{KEY}` placeholders in " +
                "`password`, `identity` and stamped certificate paths.\n" +
                "`signing_attrs()` deliberately does not provide it, because " +
                "stamping is rule-wide rather than signing-specific and " +
                "cannot be namespaced. Declare it on the rule alongside the " +
                "signing attributes:\n" +
                "    load(\"@bazel_lib//lib:stamping.bzl\", \"STAMP_ATTRS\")\n" +
                "    attrs = dict({...}, **dict(signing_attrs(), **STAMP_ATTRS))",
            )

    tool_mode = tool if tool != None else attr("tool")
    if tool_mode not in TOOL_KINDS + ["auto"]:
        fail("rules_signing: unknown tool {}; expected one of {}".format(
            repr(tool_mode),
            ", ".join(TOOL_KINDS + ["auto"]),
        ))
    for kind in require:
        if kind not in TOOL_KINDS:
            fail("rules_signing: unknown tool kind {} in `require`; expected one of {}".format(
                repr(kind),
                ", ".join(TOOL_KINDS),
            ))
        if tool_mode != "auto" and tool_mode != kind:
            fail(
                "rules_signing: `tool = \"{}\"` cannot sign this target, ".format(tool_mode) +
                "which requires {}{}.".format(
                    kind,
                    " because " + require_reason if require_reason else "",
                ),
            )

    cert = cert_info(ctx, attr_name = attr_prefix + "certificate")

    args = ctx.actions.args()

    # Written one argument per line and read back as UTF-8 by sign_tool's
    # `expand_argfiles`, so arguments survive intact regardless of the
    # platform's native command-line encoding.
    args.set_param_file_format("multiline")

    args.add("--mode", "sign")
    args.add("--tool", tool_mode)

    inputs = []
    sign_tool = getattr(ctx.executable, "_" + attr_prefix + "sign_tool")
    tools = [sign_tool]

    for kind, toolchain_type in [
        ("osslsigncode", OSSLSIGNCODE_TOOLCHAIN),
        ("cosign", COSIGN_TOOLCHAIN),
        ("codesign", CODESIGN_TOOLCHAIN),
    ]:
        tool_file = _toolchain_tool(ctx, toolchain_type)
        if tool_file == None and _needs_toolchain(srcs, tool_mode, kind, require):
            if ctx.toolchains[toolchain_type] != None:
                fail(
                    "rules_signing: the {} toolchain is resolved but does ".format(kind) +
                    "not expose an executable tool.",
                )
            _fail_missing_toolchain(
                kind,
                _needs_toolchain_reason(srcs, tool_mode, kind, require, require_reason),
                tool_mode,
            )
        args.add("--{}-tool".format(kind), tool_file.path if tool_file else "")
        if tool_file:
            inputs.append(tool_file)

    # openssl is optional and only consulted when PKCS#12 material has to be
    # converted to PEM for cosign, which cannot be known until the action runs.
    # It is therefore never required at analysis time; sign_tool raises an
    # actionable error if the conversion turns out to be necessary.
    openssl_tc = ctx.toolchains[OPENSSL_TOOLCHAIN]
    openssl_file = openssl_tc.tool if openssl_tc != None and hasattr(openssl_tc, "tool") else None
    if openssl_file:
        args.add("--openssl-tool", openssl_file.path)

        # `data` includes the tool itself plus any files it needs alongside
        # it at runtime (e.g. Windows' libcrypto/libssl DLLs); adding them
        # all as plain action inputs stages them in the sandbox next to
        # openssl.exe, which is what its same-directory DLL search needs.
        if hasattr(openssl_tc, "data"):
            inputs.extend(openssl_tc.data.to_list())
        else:
            inputs.append(openssl_file)

    if attr("timestamp_url"):
        args.add("--timestamp-url", attr("timestamp_url"))
    if attr("transparency_log"):
        args.add("--transparency-log", attr("transparency_log"))
    if attr("description"):
        args.add("--name", attr("description"))
    if attr("url"):
        args.add("--url", attr("url"))
    if attr("options"):
        args.add("--options", ",".join(attr("options")))

    entitlements = getattr(ctx.file, attr_prefix + "entitlements", None)
    if entitlements:
        args.add("--entitlements", entitlements.path)
        inputs.append(entitlements)

    inputs.extend(add_cert_args(args, cert, maybe_stamp(ctx)))

    params_file = ctx.actions.declare_file(
        "{}.sign_params".format(name if name else ctx.label.name),
    )
    ctx.actions.write(params_file, args)
    inputs.append(params_file)

    return struct(
        executable = sign_tool,
        params_file = params_file,
        inputs = depset(inputs),
        tools = tools,
        # A signer spawned by another tool does not inherit the runfiles
        # discovery Bazel sets up for an action's own executable, so point it
        # at the runfiles tree staged beside the launcher.
        env = {"RUNFILES_DIR": sign_tool.path + ".runfiles"},
        required_env_vars = [cert.password_env] if cert and cert.password_env else [],
        tool_mode = tool_mode,
    )

def signing_argv(
        sctx,
        infile = None,
        outfile = None,
        out_dir = None,
        rel_src_manifest = None,
        path_fn = None):
    """Builds a signer command line for the context returned by `signing_context`.

    Exactly one of `infile` or `rel_src_manifest` must be given.

    Args:
        sctx: the struct returned by `signing_context`.
        infile: path of the single file or directory to sign. Pass a `File`,
            or a plain string when the path is only known to the tool that
            will run the command (NSIS' `!finalize`, for instance, substitutes
            the string `"%1"`).
        outfile: where to write the signed result. When omitted, `infile` is
            signed in place, which is what compile-time hooks that hand over a
            path to an artifact they already produced expect.
        out_dir: output directory for `rel_src_manifest` mode.
        rel_src_manifest: manifest of tab-separated `relpath\\tsource` lines,
            for signing many files in one invocation.
        path_fn: optional function applied to every path in the result. Use it
            when the command is consumed by a tool that needs a different path
            spelling than Bazel's (for example a Windows-style path).

    Returns:
        A list of strings: the executable, the `--args-file` reference, and
        the arguments naming this invocation's input and output.
    """
    if (infile == None) == (rel_src_manifest == None):
        fail("rules_signing: signing_argv needs exactly one of `infile` or `rel_src_manifest`")
    if rel_src_manifest != None and out_dir == None:
        fail("rules_signing: signing_argv needs `out_dir` alongside `rel_src_manifest`")

    def path(v):
        p = v.path if type(v) == "File" else v
        return path_fn(p) if path_fn else p

    argv = [path(sctx.executable), "--args-file=" + path(sctx.params_file)]
    if infile != None:
        argv.extend(["--in", path(infile)])
        if outfile != None:
            argv.extend(["--out", path(outfile)])
    else:
        argv.extend([
            "--rel-src-manifest",
            path(rel_src_manifest),
            "--out-dir",
            path(out_dir),
        ])
    return argv

def rel_src_manifest(ctx, srcs, name = None, flatten_single_directory = None):
    """Writes the manifest that pairs each source with its output-relative path.

    Passing each (relpath, src) pair as separate `--rel`/`--src` argv tokens
    would round-trip file names through the OS's native command-line encoding.
    On Windows that's the system's ANSI code page, not UTF-8, so any relpath
    character outside it (e.g. non-Latin scripts) arrives at sign_tool
    corrupted. Writing the pairs to a manifest file instead keeps them as file
    content, which Bazel always writes and Python always reads as UTF-8,
    sidestepping the OS argv encoding entirely.

    Args:
        ctx: the rule context.
        srcs: the Files to sign.
        name: base name for the manifest file; defaults to the target name.
        flatten_single_directory: when a lone directory artifact is signed,
            write its contents at the root of the output directory instead of
            nesting them under the directory's own name. Defaults to doing so.

    Returns:
        The manifest `File`.
    """
    if flatten_single_directory == None:
        flatten_single_directory = len(srcs) == 1 and srcs[0].is_directory

    lines = []
    for f in srcs:
        relpath = "" if flatten_single_directory and f.is_directory else f.short_path
        lines.append("{}\t{}".format(relpath, f.path))

    out = ctx.actions.declare_file(
        "{}.rel_src_manifest".format(name if name else ctx.label.name),
    )
    ctx.actions.write(out, "".join([l + "\n" for l in lines]))
    return out

def sign_action(
        ctx,
        srcs,
        out_dir,
        sctx = None,
        mnemonic = "SignTree",
        progress_message = None,
        attr_prefix = "signing_",
        **kwargs):
    """Registers an action signing `srcs` into the `out_dir` tree artifact.

    This is the "sign these files and keep their layout" case that the `sign`
    rule exposes, factored out so other rules can reuse it directly.

    Args:
        ctx: the rule context.
        srcs: the Files to sign.
        out_dir: a directory artifact from `ctx.actions.declare_directory`.
        sctx: a `signing_context` to reuse; one is created if omitted.
        mnemonic: action mnemonic.
        progress_message: action progress message.
        attr_prefix: the prefix the signing attributes were declared with.
            Ignored when `sctx` is supplied.
        **kwargs: forwarded to `ctx.actions.run`.

    Returns:
        The `signing_context` that was used.
    """
    if sctx == None:
        sctx = signing_context(ctx, srcs = srcs, attr_prefix = attr_prefix)

    manifest = rel_src_manifest(ctx, srcs)
    argv = signing_argv(
        sctx,
        rel_src_manifest = manifest,
        out_dir = out_dir.path,
    )

    ctx.actions.run(
        executable = sctx.executable,
        # argv[0] is the executable itself, which ctx.actions.run supplies.
        arguments = argv[1:],
        inputs = depset(srcs + [manifest], transitive = [sctx.inputs]),
        tools = sctx.tools,
        outputs = [out_dir],
        mnemonic = mnemonic,
        progress_message = (
            progress_message if progress_message else "Signing output tree for {}".format(ctx.label)
        ),
        **kwargs
    )
    return sctx

def signing_attrs(prefix = "signing_"):
    """Returns the attributes a rule needs in order to call `signing_context`.

    This does **not** include `STAMP_ATTRS`. Stamping is a rule-wide concern
    rather than a signing-specific one -- a rule that stamps at all almost
    certainly stamps more than its signing options, and `stamp` cannot be
    prefixed because `maybe_stamp` looks it up by that exact name. Bundling it
    here would therefore mean a rule that already declares `STAMP_ATTRS` for
    its own purposes could not also use these attributes, since merging two
    dicts that share a key is an error.

    So the rule declares it, once, alongside these:

    ```starlark
    load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")

    my_rule = rule(
        attrs = dict({
            # ... your own attributes ...
        }, **dict(signing_attrs(), **STAMP_ATTRS)),
    )
    ```

    `signing_context` checks the stamp attributes are present and fails with
    an explanation if they are not. That check matters: `maybe_stamp` reads
    them with a default, so their absence would otherwise silently disable
    stamping and turn an unresolved `{KEY}` placeholder into a confusing
    downstream error rather than an obvious missing-attribute one.

    Args:
        prefix: prepended to every attribute name. The default keeps the
            signing options in their own namespace so they cannot collide with
            attributes the host rule already defines -- a real risk for names
            as generic as `tool`, `url`, `description` and `options`. Pass `""`
            for the bare names.

    Returns:
        A dict suitable for merging into a rule's `attrs`.
    """
    p = prefix
    return {
        p + "tool": attr.string(
            default = "auto",
            values = TOOL_KINDS + ["auto"],
            doc = "Which signer to use, or \"auto\" (the default) to select " +
                  "one per file from its extension and, failing that, its " +
                  "header bytes. Note that \"auto\" requires every signing " +
                  "toolchain to be registered whenever an input is a " +
                  "directory artifact or has no recognizable extension, " +
                  "because the contents that decide the signer are not " +
                  "known until the action runs. Naming a single tool " +
                  "explicitly requests only that toolchain.",
        ),
        p + "certificate": attr.label(
            providers = [[SigningCertificateInfo]],
            doc = "The `certificate` target holding the signing material. " +
                  "Without one, files are copied through unsigned, which keeps " +
                  "builds working for contributors who have no key.",
        ),
        p + "timestamp_url": attr.string(
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
        p + "transparency_log": attr.string(
            default = "",
            doc = "Rekor transparency log to publish cosign signatures to. " +
                  "Empty (the default) publishes nothing, so signing stays " +
                  "offline and no hash of your build output leaves the " +
                  "machine. Set to \"default\" to opt in to the public " +
                  "Sigstore instance, or to the URL of a specific instance " +
                  "(such as a private Rekor deployment). Enabling this makes " +
                  "every signing action a network call.",
        ),
        p + "description": attr.string(doc = "Signature description when supported."),
        p + "url": attr.string(doc = "Publisher URL when supported."),
        p + "options": attr.string_list(
            default = ["runtime"],
            doc = "codesign --options values.",
        ),
        p + "entitlements": attr.label(allow_single_file = True),
        "_" + p + "sign_tool": attr.label(
            default = "@rules_signing//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    }

SIGNING_ATTRS = signing_attrs()

SIGNING_TOOLCHAINS = [
    config_common.toolchain_type(OSSLSIGNCODE_TOOLCHAIN, mandatory = False),
    config_common.toolchain_type(COSIGN_TOOLCHAIN, mandatory = False),
    config_common.toolchain_type(CODESIGN_TOOLCHAIN, mandatory = False),
    config_common.toolchain_type(OPENSSL_TOOLCHAIN, mandatory = False),
]
