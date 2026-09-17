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
load("//signing/private:binary_kinds.bzl", "JAR", "MACHO", "PE")
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

# jarsigner ships inside every JDK, so it is resolved through rules_java's own
# runtime toolchain (the one `@bazel_tools//tools/jdk:runtime_toolchain_type`
# points at, and which Bazel registers a default for out of the box) instead
# of a toolchain this project defines and consumers must register themselves.
JARSIGNER_TOOLCHAIN = "@bazel_tools//tools/jdk:runtime_toolchain_type"

TOOL_KINDS = ["osslsigncode", "codesign", "cosign", "jarsigner"]

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

_JARSIGNER_EXT = [
    ".jar",
]

_COSIGN_SIDECAR_SUFFIXES = [".sig", ".bundle.json"]

_REGISTRATION = {
    "osslsigncode": "\"@signing_osslsigncode//:osslsigncode_toolchain\"",
    "cosign": "\"@signing_cosign//:cosign_toolchain\"",
    "codesign": "\"@codesign.bzl//toolchain:all\"",
    "jarsigner": "\"@rules_java//toolchains:all\"",
}

_FORMAT_SIGNERS = {
    PE: "osslsigncode",
    MACHO: "codesign",
    JAR: "jarsigner",
}

def _detect_tool(src, formats = {}):
    """The signer for `src`, decided entirely at analysis time.

    Two kinds of evidence, and the order between them is the point.

    1. The rule that produces the file, via `binary_format_aspect`. A rule
       that is in the table speaks for its outputs conclusively, including
       when what it has to say is that they are *not* native binaries. That
       verdict is final and step 2 is not reached.

    2. The file's name, for files no rule spoke for: prebuilts committed to
       the repository, downloads, anything a `genrule` emitted. Also the only
       possible evidence for the formats Authenticode defines by file type --
       PowerShell and JavaScript scripts, `.msi` and `.cab` installers,
       `.cat` catalogs, `.dmg`/`.pkg` images -- since no compiler emits those
       and so no rule kind can describe them.

    Letting step 1 lose to step 2 is how a `native_binary` wrapping a Linux
    ELF gets signed as a Windows PE: it names its output `<name>.exe` on
    every platform. Hence NOT_NATIVE, which is a rule saying "no" rather than
    a rule saying nothing.

    Anything still unaccounted for is signed with a detached signature, which
    is the one option that works on a file whose contents are unknown.
    """
    fmt = formats.get(src)
    if fmt != None:
        return _FORMAT_SIGNERS.get(fmt, "cosign")

    p = src.short_path.lower()
    for ext in _OSSLSIGNCODE_EXT:
        if p.endswith(ext):
            return "osslsigncode"
    for ext in _CODESIGN_EXT:
        if p.endswith(ext):
            return "codesign"
    for ext in _JARSIGNER_EXT:
        if p.endswith(ext):
            return "jarsigner"
    return "cosign"

DETACHED_SIGNATURE_MODES = ["auto", "always", "never"]

def _wants_detached(signer, detached_signatures):
    """Whether `signer`'s source gets a detached signature under this policy.

    Under `"auto"` the answer follows the routing: a source no native signer
    claims is signed by cosign, which is detached, and one a native signer
    does claim has its signature embedded instead. The other two modes answer
    the same way for every source, which is the point of them -- the output
    shape stops depending on what the source is called.
    """
    if detached_signatures == "always":
        return True
    if detached_signatures == "never":
        return False
    return signer == "cosign"

def _needs_toolchain(
        srcs,
        selected_tool,
        tool_kind,
        require,
        detached_signatures = "auto",
        formats = {}):
    if tool_kind in require:
        return True
    if selected_tool == tool_kind:
        return True

    # Every file gets a detached signature, so cosign signs even the sources a
    # native signer already claimed.
    if tool_kind == "cosign" and detached_signatures == "always":
        for f in srcs:
            return True
    if selected_tool != "auto":
        return False

    for f in srcs:
        # Directory artifact contents are only available at execution time, so
        # require every native signer: an ordinary directory may hold nested
        # exe/dll files needing osslsigncode, Mach-O binaries and nested
        # .app/.dmg/.pkg bundles needing codesign, or jars needing jarsigner.
        if f.is_directory:
            return True

        # Every file is classified during analysis, so only the toolchains
        # actually selected are asked for. A file whose producing rule is
        # unknown to detection and whose name says nothing is signed with a
        # detached signature rather than forcing every toolchain to be
        # registered against the chance that it turns out to be a binary.
        if _detect_tool(f, formats) == tool_kind:
            return True
    return False

def _needs_toolchain_reason(
        srcs,
        selected_tool,
        tool_kind,
        require,
        require_reason,
        detached_signatures = "auto",
        formats = {}):
    """Explains why `tool_kind` was required, for the failure message.

    With an explicit `tool` the answer is trivial, but under `auto` the
    requirement usually comes from a particular input, which is worth naming
    rather than leaving the reader to work out which of their sources asked
    for a toolchain they have not registered.
    """
    if tool_kind in require:
        if require_reason:
            return require_reason
        return "this rule always signs with {}".format(tool_kind)
    if selected_tool == tool_kind:
        return "`tool = \"{}\"` was requested".format(tool_kind)

    if tool_kind == "cosign" and detached_signatures == "always":
        return (
            "`detached_signatures = \"always\"` gives every file a `.sig` " +
            "and `.bundle.json`, which cosign produces"
        )

    for f in srcs:
        if f.is_directory:
            return (
                "`tool = \"auto\"` and '{}' is a directory artifact, whose ".format(f.short_path) +
                "contents are only known when the action runs, so every " +
                "signer must be available"
            )
        if _detect_tool(f, formats) == tool_kind:
            if formats.get(f):
                if formats[f] == JAR:
                    return "'{}' is built as a jar".format(f.short_path)
                return (
                    "'{}' is built as a {} binary".format(
                        f.short_path,
                        "Windows PE" if formats[f] == PE else "Mach-O",
                    )
                )
            if f in formats:
                return (
                    "'{}' is built by a rule that produces no natively ".format(f.short_path) +
                    "signable binary, so it gets a detached signature"
                )
            return "'{}' is signed with {} because of its name".format(
                f.short_path,
                tool_kind,
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
    accepted rather than special-casing the caller. `toolchain_type` may not
    even be declared on this rule -- `signing_toolchains()` lets a rule that
    structurally can never need a given signer skip declaring its toolchain
    type at all -- and indexing `ctx.toolchains` with an undeclared type is a
    hard error, unlike a declared-but-unresolved one, which just reads back
    `None`. The membership check tells the two apart before it matters.
    """
    if toolchain_type not in ctx.toolchains:
        return None
    tc = ctx.toolchains[toolchain_type]
    if tc == None:
        return None
    for field in ["tool", "codesign"]:
        f = getattr(tc, field, None)
        if f != None:
            return f
    return None

def _jarsigner_tool_and_support_files(ctx):
    """Returns `(jarsigner File, support files)`, or `(None, [])` if unresolved.

    jarsigner is not exposed by a `ToolchainInfo.tool` field the way the other
    signers are: `@bazel_tools//tools/jdk:runtime_toolchain_type` resolves to
    a `java_runtime`, whose `files` carry the whole JDK tree, jarsigner
    included. jarsigner is a real dynamically-linked binary that loads shared
    libraries from elsewhere in that tree (`libjli`, `libjava`, ...), so the
    entire tree -- not just the one file -- has to reach the sandbox as the
    action's inputs, exactly as `openssl_toolchain`'s `data` does for
    Windows' DLLs.

    `JARSIGNER_TOOLCHAIN` may not even be declared on this rule --
    `signing_toolchains(jarsigner = False)` opts a rule that will never sign
    a `.jar` out of it -- and indexing `ctx.toolchains` with an undeclared
    type is a hard error, so that is checked before it matters.
    """
    if JARSIGNER_TOOLCHAIN not in ctx.toolchains:
        return None, []
    tc = ctx.toolchains[JARSIGNER_TOOLCHAIN]
    if tc == None:
        return None, []
    runtime = getattr(tc, "java_runtime", None)
    if runtime == None:
        return None, []
    files = runtime.files.to_list()
    for f in files:
        if f.basename == "jarsigner" or f.basename == "jarsigner.exe":
            return f, files
    return None, []

def signing_context(
        ctx,
        srcs = [],
        require = [],
        require_reason = "",
        tool = None,
        detached_signatures = None,
        formats = {},
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
        require: tool kinds (`"osslsigncode"`, `"codesign"`, `"cosign"`,
            `"jarsigner"`) that this rule always needs regardless of `srcs`.
            Use this when the signing target does not exist at analysis
            time, so that a missing toolchain fails during analysis with a
            clear message rather than part-way through the action.
        require_reason: human-readable explanation of `require`, quoted in the
            missing-toolchain error. For example "an NSIS uninstaller is
            always a PE executable".
        tool: overrides the `tool` attribute. Rules that only ever produce one
            kind of artifact can pin the signer here instead of exposing the
            choice.
        detached_signatures: overrides the `detached_signatures` attribute.
        formats: `File` to binary-format mapping from `binary_formats()`,
            naming the sources that are native binaries. Sources absent from
            it are classified by name instead, so passing nothing is valid
            and simply means no rule vouched for anything.
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
        * `detached_signatures`: the resolved value of `detached_signatures`.
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

    detached_mode = (
        detached_signatures if detached_signatures != None else attr("detached_signatures")
    )
    if detached_mode not in DETACHED_SIGNATURE_MODES:
        fail("rules_signing: unknown detached_signatures {}; expected one of {}".format(
            repr(detached_mode),
            ", ".join(DETACHED_SIGNATURE_MODES),
        ))

    # cosign signs nothing but detached signatures, so turning them off leaves
    # it with nothing to do -- every file would simply be copied, which is
    # unlikely to be what a target that explicitly asked for cosign wants.
    if tool_mode == "cosign" and detached_mode == "never":
        fail(
            "rules_signing: `tool = \"cosign\"` signs by producing a detached " +
            "signature, but `detached_signatures = \"never\"` forbids one, so " +
            "this target would only copy its sources.\n" +
            "Drop `detached_signatures`, or drop `certificate` if unsigned " +
            "copies are what you want.",
        )
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
    args.add("--detached-signatures", detached_mode)

    inputs = []
    sign_tool = getattr(ctx.executable, "_" + attr_prefix + "sign_tool")
    tools = [sign_tool]

    for kind, toolchain_type in [
        ("osslsigncode", OSSLSIGNCODE_TOOLCHAIN),
        ("cosign", COSIGN_TOOLCHAIN),
        ("codesign", CODESIGN_TOOLCHAIN),
    ]:
        tool_file = _toolchain_tool(ctx, toolchain_type)
        if tool_file == None and _needs_toolchain(
            srcs,
            tool_mode,
            kind,
            require,
            detached_mode,
            formats,
        ):
            if toolchain_type in ctx.toolchains and ctx.toolchains[toolchain_type] != None:
                fail(
                    "rules_signing: the {} toolchain is resolved but does ".format(kind) +
                    "not expose an executable tool.",
                )
            _fail_missing_toolchain(
                kind,
                _needs_toolchain_reason(
                    srcs,
                    tool_mode,
                    kind,
                    require,
                    require_reason,
                    detached_mode,
                    formats,
                ),
                tool_mode,
            )
        if tool_file:
            args.add("--{}-tool".format(kind), tool_file.path if tool_file else "")
            inputs.append(tool_file)

    # jarsigner is resolved separately: it comes from rules_java's runtime
    # toolchain rather than one of this project's own, so it is neither a
    # `ToolchainInfo.tool` field `_toolchain_tool` understands nor a single
    # file -- the whole JDK tree it was found in has to travel with it.
    jarsigner_file, jarsigner_support_files = _jarsigner_tool_and_support_files(ctx)
    if jarsigner_file == None and _needs_toolchain(
        srcs,
        tool_mode,
        "jarsigner",
        require,
        detached_mode,
        formats,
    ):
        if JARSIGNER_TOOLCHAIN in ctx.toolchains and ctx.toolchains[JARSIGNER_TOOLCHAIN] != None:
            fail(
                "rules_signing: a JDK toolchain is resolved but it does not " +
                "include jarsigner (a JRE-only distribution?). Point the " +
                "JDK toolchain at a full JDK, for example with " +
                "--java_runtime_version.",
            )
        _fail_missing_toolchain(
            "jarsigner",
            _needs_toolchain_reason(
                srcs,
                tool_mode,
                "jarsigner",
                require,
                require_reason,
                detached_mode,
                formats,
            ),
            tool_mode,
        )
    if jarsigner_file:
        args.add("--jarsigner-tool", jarsigner_file.path)
        inputs.extend(jarsigner_support_files)

    # openssl is optional and only consulted when PKCS#12 material has to be
    # converted to PEM for cosign, which cannot be known until the action runs.
    # It is therefore never required at analysis time; sign_tool raises an
    # actionable error if the conversion turns out to be necessary. Not every
    # rule declares `OPENSSL_TOOLCHAIN` (see `signing_toolchains`), so this
    # is skipped entirely rather than indexing `ctx.toolchains` with a type
    # that was never declared.
    openssl_tc = ctx.toolchains[OPENSSL_TOOLCHAIN] if OPENSSL_TOOLCHAIN in ctx.toolchains else None
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
        detached_signatures = detached_mode,
    )

def signing_argv(
        sctx,
        infile = None,
        outfile = None,
        out_dir = None,
        rel_src_manifest = None,
        require_detached_signatures = False,
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
            optionally with a third `\\tsigner` field, for signing many files
            in one invocation.
        require_detached_signatures: declares that the caller has already
            declared `.sig`/`.bundle.json` outputs for every source the
            manifest routes to cosign, so the signer must fail rather than
            fall back to copying when no certificate resolves.
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
        if require_detached_signatures:
            argv.append("--require-detached-signatures")
    return argv

def rel_src_manifest(
        ctx,
        srcs,
        name = None,
        flatten_single_directory = None,
        signers = None):
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
        signers: optional dict keyed by source path, naming the signer whose
            outputs the caller has already declared for that source. Recorded
            as a third manifest field so the action cannot produce a different
            set of files than the one analysis promised.

    Returns:
        The manifest `File`.
    """
    if flatten_single_directory == None:
        flatten_single_directory = len(srcs) == 1 and srcs[0].is_directory

    lines = []
    for f in srcs:
        relpath = "" if flatten_single_directory and f.is_directory else f.short_path
        signer = signers.get(f.path, "") if signers else ""
        lines.append("{}\t{}\t{}".format(relpath, f.path, signer))

    out = ctx.actions.declare_file(
        "{}.rel_src_manifest".format(name if name else ctx.label.name),
    )
    ctx.actions.write(out, "".join([l + "\n" for l in lines]))
    return out

def _output_relpath(src):
    """The path `src` keeps inside the output, as a valid declared-file name.

    `short_path` spells a file from another repository as `../repo/...`, which
    `declare_file` rejects because it escapes the target's own output
    directory. Everything else is already relative and is kept verbatim so the
    output mirrors the source layout.
    """
    if src.short_path.startswith("../"):
        return "external/" + src.short_path[len("../"):]
    return src.short_path

def signed_outputs(
        ctx,
        srcs,
        out_name = None,
        tool = None,
        detached_signatures = None,
        formats = {},
        attr_prefix = "signing_"):
    """Declares one output artifact per source, plus cosign's sidecar files.

    Every source keeps its own shape: a file is signed into a file and a
    directory into a directory, both under their source-relative path, rather
    than the whole target collapsing into one output tree. Sources routed to
    cosign additionally get the `.sig` and `.bundle.json` files that a
    detached signature consists of.

    Which signer each source is routed to is decided here, and entirely from
    what analysis knows: first the rule that builds the file, which reports
    whether it is a native binary and in which format, and failing that the
    source's name, for files no rule vouched for. The choice is recorded in
    the manifest and the action is bound to it, so the files that appear are
    always the files declared here, and each source is signed exactly once.

    Nothing is re-decided at execution time. A file that reaches a native
    signer has its signature embedded and needs no sidecar; one that does not
    gets a detached signature and no embedded one. Because the signer is
    settled before the build, those two facts can be declared together
    instead of one of them being discovered too late to affect the other.

    `detached_signatures` overrides the routing question for every source at
    once: `"always"` gives each of them a `.sig` and `.bundle.json` whatever
    its name, so the output shape stops depending on the sources entirely, and
    `"never"` gives none of them any, leaving only the signatures native
    signers embed.

    Args:
        ctx: the rule context.
        srcs: the Files to sign.
        out_name: directory the outputs are placed under, relative to the
            package. Defaults to `<target name>.signed`.
        tool: overrides the `tool` attribute, for rules that pin the signer.
        detached_signatures: overrides the `detached_signatures` attribute,
            which decides which sources get `.sig`/`.bundle.json` files.
        formats: `File` to binary-format mapping from `binary_formats()`.
        attr_prefix: the prefix the signing attributes were declared with.

    Returns:
        A struct with:

        * `files`: every declared output, for `DefaultInfo` and the action.
        * `signed`: just the signed counterparts of `srcs`, in `srcs` order,
          without the sidecar files.
        * `signers`: dict keyed by source path naming the signer chosen for
          it, to pass to `rel_src_manifest`.
        * `out_dir`: the path the action writes the tree under.
        * `flatten_single_directory`: what `rel_src_manifest` must be told so
          its relpaths line up with these outputs.
        * `require_detached_signatures`: whether sidecar files were declared
          and so have to be produced.
    """
    tool_mode = tool if tool != None else getattr(ctx.attr, attr_prefix + "tool")
    detached_mode = (
        detached_signatures if detached_signatures != None else getattr(
            ctx.attr,
            attr_prefix + "detached_signatures",
        )
    )
    name = out_name if out_name else "{}.signed".format(ctx.label.name)

    # A lone directory is the whole output, so its contents sit at the root
    # rather than nested under a copy of the directory's own name.
    flatten = len(srcs) == 1 and srcs[0].is_directory

    # Signing material that does not exist is not an error: files are copied
    # through unsigned so a contributor without a key can still build (see the
    # `certificate` attribute). There is then no detached signature to declare.
    cert = cert_info(ctx, attr_name = attr_prefix + "certificate")
    has_cert = cert != None and cert.certificate != None

    # `"always"` is a promise about every output this target has, and a `.sig`
    # cannot be promised without something to sign with. Copying files through
    # unsigned stays available -- it is just no longer something this mode can
    # fall into silently.
    if detached_mode == "always" and not has_cert:
        fail(
            "rules_signing: `detached_signatures = \"always\"` gives every " +
            "source a `.sig` and `.bundle.json`, but no certificate is " +
            "configured on this target, so there is nothing to sign them " +
            "with.\n" +
            "Set `certificate`, or drop `detached_signatures` to sign " +
            "whatever material happens to resolve.",
        )

    files = []
    signed = []
    signers = {}
    require_detached = False

    # Two outputs cannot share a path, and a detached signature's file names
    # are derived from the file it signs, so a target holding both `notes.md`
    # and `notes.md.sig` would ask for the same output twice. Bazel would
    # reject that on its own, but not in terms of what caused it.
    claimed = {}

    def claim(path, src, why):
        if path in claimed:
            fail(
                "rules_signing: {} and {} would both be written to {}{}.\n".format(
                    claimed[path],
                    src.short_path,
                    path,
                    why,
                ) +
                "Sign them in separate targets, or rename one of them.",
            )
        claimed[path] = src.short_path

    for src in srcs:
        relpath = _output_relpath(src)

        if src.is_directory:
            # The files inside are only known when the action runs, which is
            # what a tree artifact exists for. Nothing about it is declared
            # per file, so the per-source signer is not pinned either.
            claim(relpath, src, "")
            out = ctx.actions.declare_directory(name if flatten else name + "/" + relpath)
            files.append(out)
            signed.append(out)
            continue

        signer = tool_mode if tool_mode != "auto" else _detect_tool(src, formats)
        signers[src.path] = signer

        claim(relpath, src, "")
        out = ctx.actions.declare_file(name + "/" + relpath)
        files.append(out)
        signed.append(out)

        # Without signing material cosign copies the file through unsigned,
        # which is deliberate (see the `certificate` attribute), and there is
        # then no detached signature to declare.
        if _wants_detached(signer, detached_mode) and has_cert:
            require_detached = True
            for suffix in _COSIGN_SIDECAR_SUFFIXES:
                claim(
                    relpath + suffix,
                    src,
                    ", which is where its detached signature goes",
                )
                files.append(ctx.actions.declare_file(name + "/" + relpath + suffix))

    return struct(
        files = files,
        signed = signed,
        signers = signers,
        out_dir = _out_dir_path(ctx, name),
        flatten_single_directory = flatten,
        require_detached_signatures = require_detached,
    )

def _out_dir_path(ctx, name):
    """Exec path of the directory the declared outputs live under.

    The action needs the root to write into, but in this mode that root is
    not itself an artifact -- the files inside it are. It is spelled the same
    way `declare_file` spells its own outputs.
    """
    parts = [ctx.bin_dir.path]
    if ctx.label.workspace_root:
        parts.append(ctx.label.workspace_root)
    if ctx.label.package:
        parts.append(ctx.label.package)
    parts.append(name)
    return "/".join(parts)

def sign_action(
        ctx,
        srcs,
        out_dir = None,
        outs = None,
        sctx = None,
        formats = {},
        mnemonic = "SignTree",
        progress_message = None,
        attr_prefix = "signing_",
        **kwargs):
    """Registers an action signing `srcs`, keeping their relative layout.

    This is the "sign these files and keep their layout" case that the `sign`
    rule exposes, factored out so other rules can reuse it directly. Pass
    exactly one of:

    * `outs`, from `signed_outputs`, to get one output artifact per source
      (plus cosign's sidecar files), which is what `sign` itself does; or
    * `out_dir`, to collect everything into a single tree artifact instead,
      for rules that want one directory to hand downstream.

    Args:
        ctx: the rule context.
        srcs: the Files to sign.
        out_dir: a directory artifact from `ctx.actions.declare_directory`.
        outs: the struct returned by `signed_outputs`.
        sctx: a `signing_context` to reuse; one is created if omitted.
        formats: `File` to binary-format mapping from `binary_formats()`.
            Ignored when `sctx` is supplied, which already resolved them.
        mnemonic: action mnemonic.
        progress_message: action progress message.
        attr_prefix: the prefix the signing attributes were declared with.
            Ignored when `sctx` is supplied.
        **kwargs: forwarded to `ctx.actions.run`.

    Returns:
        The `signing_context` that was used.
    """
    if (out_dir == None) == (outs == None):
        fail("rules_signing: sign_action needs exactly one of `out_dir` or `outs`")

    if sctx == None:
        sctx = signing_context(
            ctx,
            srcs = srcs,
            formats = formats,
            attr_prefix = attr_prefix,
        )

    if outs != None:
        manifest = rel_src_manifest(
            ctx,
            srcs,
            flatten_single_directory = outs.flatten_single_directory,
            signers = outs.signers,
        )
        argv = signing_argv(
            sctx,
            rel_src_manifest = manifest,
            out_dir = outs.out_dir,
            require_detached_signatures = outs.require_detached_signatures,
        )
        outputs = outs.files
    else:
        manifest = rel_src_manifest(ctx, srcs)
        argv = signing_argv(
            sctx,
            rel_src_manifest = manifest,
            out_dir = out_dir.path,
        )
        outputs = [out_dir]

    ctx.actions.run(
        executable = sctx.executable,
        # argv[0] is the executable itself, which ctx.actions.run supplies.
        arguments = argv[1:],
        inputs = depset(srcs + [manifest], transitive = [sctx.inputs]),
        tools = sctx.tools,
        outputs = outputs,
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
                  "one per file: from the rule that builds it where that is " +
                  "known, and otherwise from its extension. Note that " +
                  "\"auto\" requires every signing toolchain to be " +
                  "registered whenever an input is a directory artifact, " +
                  "because a tree's contents are not known until the action " +
                  "runs. Individual files request only the toolchains they " +
                  "actually select. Naming a single tool explicitly " +
                  "requests only that toolchain.",
        ),
        p + "detached_signatures": attr.string(
            default = "auto",
            values = DETACHED_SIGNATURE_MODES,
            doc = "Which sources get the `.sig` and `.bundle.json` files a " +
                  "detached signature consists of. \"auto\" (the default) " +
                  "gives them to the sources no native signer claims, since " +
                  "a detached signature is the only kind they can have, and " +
                  "leaves natively signed artifacts to carry their signature " +
                  "embedded. \"always\" gives every source both, so the " +
                  "outputs of this target stop depending on what its sources " +
                  "are called, at the cost of a cosign invocation per file " +
                  "and a second signature to distribute keys and " +
                  "verification instructions for; it requires a certificate. " +
                  "\"never\" emits neither, leaving only the signatures " +
                  "native signers embed and copying through anything that " +
                  "has no native signer.",
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
                  "use (Apple's for codesign, DigiCert's for osslsigncode and " +
                  "jarsigner), " +
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

def signing_toolchains(
        osslsigncode = True,
        cosign = True,
        codesign = True,
        openssl = True,
        jarsigner = True):
    """Returns the toolchain types a rule needs in order to call `signing_context`.

    All of these are `mandatory = False`: a rule that never resolves a given
    toolchain (because none of its sources ever select that signer) builds
    fine without it registered, and `signing_context` reports a clear error,
    naming the source that needed it, only for a toolchain that *was*
    actually required and is missing.

    So the arguments below exist to let a rule that structurally can never
    need a given signer - because it only ever signs one kind of artifact -
    skip declaring that toolchain type at all, rather than to work around
    `mandatory = False` not being enough on its own. It usually is enough:
    most of these toolchain types have no candidate registered unless this
    project's own extension registered one, so a rule declaring one it never
    uses costs nothing. `jarsigner` is the exception, and the reason this
    function takes arguments instead of always returning every type. It
    resolves through `@bazel_tools//tools/jdk:runtime_toolchain_type`, which
    almost every Bazel workspace has a matching candidate registered for
    already, whether or not that workspace uses Java for anything --
    `rules_java`'s autodetected `local_jdk` registers unconditionally. On a
    machine with no system JDK, analyzing *that* candidate fails outright,
    and Bazel does not fall back to a different one just because the first
    candidate it matched turned out to be broken. Declaring this toolchain
    type on a rule can therefore make that rule fail to build on such a
    machine even when `tool` never resolves to `jarsigner` for any of its
    sources, and even though the toolchain itself is `mandatory = False`.

    Args:
        osslsigncode: whether to declare `OSSLSIGNCODE_TOOLCHAIN`, needed to
            sign Windows PE binaries (`.exe`, `.dll`, ...).
        cosign: whether to declare `COSIGN_TOOLCHAIN`, needed for detached
            `.sig`/`.bundle.json` signatures and anything with no native
            signer.
        codesign: whether to declare `CODESIGN_TOOLCHAIN`, needed to sign
            Mach-O binaries and `.app`/`.pkg`/`.dmg` bundles.
        openssl: whether to declare `OPENSSL_TOOLCHAIN`. Only consulted when
            `cosign` has to convert PKCS#12 certificate material to PEM,
            which cannot be known until the signing action runs, so `cosign`
            still requires this whenever it might be used with such
            material.
        jarsigner: whether to declare `JARSIGNER_TOOLCHAIN`. Set to `False`
            for a rule that signs no `.jar`s or other JVM binaries, so it
            never needs a Java runtime toolchain resolved and cannot be
            broken by one that fails to analyze. Defaults to `True`, which is
            what `SIGNING_TOOLCHAINS` uses.

    Returns:
        A list suitable for a rule's `toolchains`.
    """
    toolchains = []
    if osslsigncode:
        toolchains.append(config_common.toolchain_type(OSSLSIGNCODE_TOOLCHAIN, mandatory = False))
    if cosign:
        toolchains.append(config_common.toolchain_type(COSIGN_TOOLCHAIN, mandatory = False))
    if codesign:
        toolchains.append(config_common.toolchain_type(CODESIGN_TOOLCHAIN, mandatory = False))
    if openssl:
        toolchains.append(config_common.toolchain_type(OPENSSL_TOOLCHAIN, mandatory = False))
    if jarsigner:
        toolchains.append(config_common.toolchain_type(JARSIGNER_TOOLCHAIN, mandatory = False))
    return toolchains

SIGNING_TOOLCHAINS = signing_toolchains()
