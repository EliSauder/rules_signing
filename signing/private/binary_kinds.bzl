"""Which rules produce native binaries, and which of their outputs are ones.

A signer can only be chosen for a file that is known to be a Windows PE or a
macOS Mach-O. Reading the file to find out is not available while the build
graph is being built, because the file has not been produced yet -- so this
table answers from the one thing analysis does have, which is the rule that
produces it.

Rules are matched by `ctx.rule.kind`, the rule's name as a plain string.
Nothing here loads a ruleset, which is deliberate: a table keyed by strings
can describe `go_binary` without `rules_go` being in the module graph, and a
build that has never heard of Rust pays nothing for the Rust entries. It also
means this file has no dependencies to keep in sync.

The corollary is that the names have to be the *rule's*, not the macro's.
Rulesets commonly expose `foo_binary` as a macro wrapping a rule called
`_foo_binary`, and only the latter ever reaches `ctx.rule.kind`.

## Adding a ruleset

Add one row per rule. The entry says which of the rule's outputs are native
binaries, and nothing else -- the *format* (PE or Mach-O) comes from the
configuration the rule was analysed in, so a row does not have to care which
platform it is being built for:

    "my_binary": executable(),          # the rule's executable output
    "my_shared_library": all_outputs(), # every output is a native library
    "my_copy_rule": forward("src"),     # bytes come from another target

`jar_outputs()` is the odd one out: it does not describe a native binary at
all, but a `.jar` archive jarsigner can embed a signature into, for rules
(any JVM ruleset's `_binary`/`_library`/`_import`) whose executable output is
a launcher script beside the actual jar rather than the jar itself.

`forward` is what makes rules that move bytes around without changing them --
copies, renames, platform wrappers -- transparent to detection, so a binary
does not stop being recognisable for having been through one.

A rule that is *not* in this table produces no native binaries as far as
signing is concerned, which is the right answer for scripts, archives and
data -- as long as nothing it emits happens to be named like a native binary
that a fallback by extension would misread. Entries like `py_binary` below
are `not_native()`, which conclusively marks every output NOT_NATIVE instead
of relying on that being true by omission: it is what stops the Windows stub
those rules name `<name>.exe` from being read by that name and handed to a
native signer.
"""

# Formats a native signer exists for. ELF is deliberately absent: Linux
# binaries carry no signature of their own, so an ELF is signed the same way
# any other file without a native format is.
PE = "pe"
MACHO = "macho"

# Unlike PE and MACHO, a jar is a jar on every platform: it is a zip archive
# holding class files, not a compiled machine binary, so nothing about it
# depends on the configuration a rule was analysed in. jar_outputs() below
# pins it rather than reading it from the platform for that reason.
JAR = "jar"

# A verdict of "this file is not a natively signable binary", as opposed to no
# verdict at all. The difference matters: a file nothing vouched for falls back
# to being judged by its name, and for a file a rule *has* spoken for that
# fallback would be free to overrule it. `native_binary` is the case that
# forces the distinction -- it names its output `<name>.exe` on every
# platform, Linux included, so an extension consulted afterwards would call a
# perfectly ordinary ELF a Windows PE and hand it to osslsigncode.
NOT_NATIVE = ""

# Entry kinds. Their values are the strings a row carries, so a malformed
# table fails loudly at load time rather than silently classifying nothing.
_EXECUTABLE = "executable"
_ALL_OUTPUTS = "all_outputs"
_JAR_OUTPUTS = "jar_outputs"
_FORWARD = "forward"
_NOT_NATIVE = "not_native"

def executable(format = None):
    """The rule's executable output is a native binary.

    This is `DefaultInfo.files_to_run.executable`, which every rule declaring
    `executable = True` sets, whatever language it is written for. Data files
    and other outputs the rule carries are left unclassified.

    Args:
        format: pins the binary format instead of taking it from the
            configuration. Only for rules whose output format does not follow
            the target platform, such as .NET assemblies, which are PE
            everywhere.
    """
    return struct(kind = _EXECUTABLE, attrs = [], format = format, names_are_evidence = True)

def all_outputs(format = None):
    """Every file the rule reports in `DefaultInfo` is a native binary.

    For rules whose whole output *is* the artifact -- a shared library rule,
    typically. Do not use it for rules that also emit headers, manifests or
    data alongside.

    Args:
        format: as for `executable`.
    """
    return struct(kind = _ALL_OUTPUTS, attrs = [], format = format, names_are_evidence = True)

def jar_outputs():
    """The `.jar` files among the rule's outputs are jarsigner-signable.

    For rules whose executable output is a launcher script beside the actual
    artifact -- `java_binary`'s shell/batch stub, `kt_jvm_binary`'s `.jdeps` --
    `executable()` and `all_outputs()` both pick the wrong thing: the former
    finds the launcher, not the jar, and the latter would hand jarsigner a
    launcher script it cannot sign. Only the outputs actually named `.jar` get
    a verdict here; everything else the rule reports is left unclassified,
    which is what lets a launcher fall back to being judged by its own name
    (ordinarily nothing, so it is signed with a detached signature) instead of
    being misread as a jar itself.
    """
    return struct(kind = _JAR_OUTPUTS, attrs = [], format = JAR, names_are_evidence = True)

def forward(*attrs, **kwargs):
    """The rule passes another target's bytes through unchanged.

    A copy or a rename does not make a PE stop being a PE, so the
    classification of the named attributes' targets carries over to this
    rule's outputs. Only used when the rule produces as many files as it took
    in, since anything else is repackaging rather than passing through.

    Args:
        *attrs: attribute names holding the targets the bytes come from.
        **kwargs: `output_names_are_evidence` (default True) -- whether this
            rule's output names may be read as a hint about their contents.
            Set it False for a rule that names its output itself instead of
            keeping the name it was given: `native_binary` calls its output
            `<name>.exe` on Linux as readily as on Windows, so the name says
            only what that rule's author chose and nothing about the bytes.
            An output that cannot be classified is then recorded as not
            natively signable rather than left for its extension to answer
            for. This describes what the third-party rule does; rules_signing
            never renames anything.
    """
    names_are_evidence = kwargs.pop("output_names_are_evidence", True)
    if kwargs:
        fail("forward() got unexpected keyword arguments: {}".format(sorted(kwargs)))
    return struct(
        kind = _FORWARD,
        attrs = list(attrs),
        format = None,
        names_are_evidence = names_are_evidence,
    )

def not_native(reason = ""):
    """The rule's outputs are conclusively not native binaries.

    Unlike an absent rule, this is not silence: every file the rule reports
    in `DefaultInfo` is recorded as `NOT_NATIVE`, the same forced verdict
    `forward(output_names_are_evidence = False)` gives a copy rule that names
    its own outputs. That is what keeps a launcher a ruleset names `<name>.exe`
    on Windows -- `sh_binary`, `py_binary` and the rest all do this for their
    Windows stub -- from being read by that name afterwards and handed to a
    native signer it was never meant for.

    Args:
        reason: why, quoted in documentation and nothing else.
    """
    return struct(kind = _NOT_NATIVE, attrs = [], format = None, names_are_evidence = True, reason = reason)

# ---------------------------------------------------------------------------
# The table
#
# One row per rule, grouped by ruleset. See the module docstring for the
# shape of a row and for why the names are rules rather than macros.
# ---------------------------------------------------------------------------

RULE_KINDS = {
    # --- rules_cc -----------------------------------------------------------
    # `cc_library` is absent on purpose: its static archives are not signable,
    # and the shared library a `cc_shared_library` builds from it belongs to
    # that rule instead.
    "cc_binary": executable(),
    "cc_test": executable(),
    "cc_shared_library": all_outputs(),

    # --- rules_go -----------------------------------------------------------
    # The `go_binary` macro picks a different rule for non-executable link
    # modes (`c-shared`, `c-archive`, `plugin`), so both names appear here.
    "go_binary": executable(),
    "go_test": executable(),
    "go_non_executable_binary": all_outputs(),
    "go_cross_binary": forward("target"),

    # --- rules_rust ---------------------------------------------------------
    # `rust_library` builds `.rlib`, and `rust_static_library` a `.a`; neither
    # is signable. `rust_proc_macro` is a real dynamic library, but it is
    # built in the exec configuration, which the aspect reads correctly.
    "rust_binary": executable(),
    "rust_test": executable(),
    "rust_shared_library": all_outputs(),
    "rust_dylib_library": all_outputs(),
    "rust_proc_macro": all_outputs(),

    # --- rules_swift --------------------------------------------------------
    "swift_binary": executable(),
    "swift_test": executable(),

    # --- rules_apple --------------------------------------------------------
    # Bundles are directory artifacts and are handled as trees, not here. Only
    # the rules whose output is a bare Mach-O appear. rules_apple signs its
    # own output already, so these rows exist to classify, not to recommend
    # signing twice -- see the README.
    "macos_dylib": all_outputs(),
    "macos_command_line_application": executable(),
    "apple_universal_binary": all_outputs(),

    # --- rules_dotnet -------------------------------------------------------
    # A managed assembly is a PE on every host, so the format is pinned rather
    # than taken from the target platform. The rules' executable output is a
    # `.sh`/`.bat` launcher, not the assembly, so `executable()` would pick
    # the wrong file -- the `.dll` is what lands in `DefaultInfo.files`.
    "csharp_library": all_outputs(format = PE),
    "fsharp_library": all_outputs(format = PE),

    # --- JVM rulesets --------------------------------------------------------
    # A `.jar` is a zip, not a compiled binary, but jarsigner can embed a
    # signature in one directly, so it gets a verdict here rather than being
    # `not_native()` like every other archive format. Every ruleset that
    # builds one shares the same output shape: the jar plus a launcher script
    # (`java_binary`'s shell/batch stub, `kt_jvm_binary`'s `.jdeps`) that is
    # not itself a jar and is left for `jar_outputs()` to skip.
    "java_binary": jar_outputs(),
    "java_test": jar_outputs(),
    "java_library": jar_outputs(),
    "java_import": jar_outputs(),
    "kt_jvm_binary": jar_outputs(),
    "kt_jvm_test": jar_outputs(),
    "kt_jvm_library": jar_outputs(),
    "kt_jvm_import": jar_outputs(),
    "scala_binary": jar_outputs(),
    "scala_test": jar_outputs(),
    "scala_repl": jar_outputs(),
    "scala_library": jar_outputs(),
    "scala_macro_library": jar_outputs(),
    "scala_import": jar_outputs(),

    # --- rules_zig ----------------------------------------------------------
    "zig_binary": executable(),
    "zig_test": executable(),
    "zig_shared_library": all_outputs(),
    "zig_configure_binary": forward("actual"),
    "zig_configure_test": forward("actual"),

    # --- rules_d ------------------------------------------------------------
    "d_binary": executable(),
    "d_test": executable(),

    # --- rules_haskell ------------------------------------------------------
    # Macro-wrapped: the public `haskell_binary` is a macro over a rule whose
    # name carries a leading underscore. Read from source rather than proven
    # with a live fixture: rules_haskell 1.0 does not load under Bazel 9.1 --
    # it still calls the native `sh_binary`, which Bazel 9 removed -- so this
    # repository cannot build one to check.
    "_haskell_binary": executable(),
    "_haskell_test": executable(),
    "haskell_cabal_binary": executable(),

    # --- pass-through rules -------------------------------------------------
    # Copies, renames, groupings and platform wrappers move bytes without
    # changing what they are, so a binary stays recognisable through one.
    # Names with a leading underscore are the rules behind same-named macros
    # in aspect_bazel_lib and bazel_skylib, which share these kind strings.
    "filegroup": forward("srcs"),
    "_copy_file": forward("src"),
    "_copy_xfile": forward("src"),
    "_copy_to_bin": forward("srcs"),
    "output_files": forward("target"),
    "select_file": forward("srcs"),
    "platform_transition_filegroup": forward("srcs"),
    "platform_transition_binary": forward("binary"),
    "platform_transition_test": forward("binary"),
    "extra_toolchains_transitioned_foreign_cc_target": forward("target"),

    # `native_binary` and `native_test` name their output `<name>.exe` on
    # every platform, Linux included, so an output they could not classify
    # must not fall through to being judged by that name.
    "native_binary": forward("src", output_names_are_evidence = False),
    "native_test": forward("src", output_names_are_evidence = False),

    # --- deliberately not native --------------------------------------------
    # Each of these is executable and would look like a plausible row.
    "py_binary": not_native(
        "a bootstrap script, or on Windows a prebuilt launcher carrying an " +
        "appended configuration blob that Authenticode signing would be " +
        "liable to corrupt",
    ),
    "py_test": not_native("as py_binary"),
    "sh_binary": not_native("a shell script, or on Windows a stub launcher"),
    "sh_test": not_native("as sh_binary"),
    # Not proven with a live fixture: rules_perl's bzlmod extension always
    # registers its repos as a non-dev dependency of whichever module calls
    # it (bazel-contrib/rules_perl's `perl_repositories` hardcodes
    # `root_module_direct_deps = "all"`, unlike bazel_skylib's
    # `modules.use_all_repos`, which checks first). A dev-only ruleset using
    # it as a dev dependency cannot stay root-buildable, so this row is read
    # from source rather than built here.
    "perl_binary": not_native("a script wrapping the perl interpreter"),
    "perl_test": not_native("as perl_binary"),
    "js_binary": not_native("a `.sh`/`.bat` launcher beside its JS sources"),
    "js_test": not_native("as js_binary"),
    "cc_library": not_native("static archives, which carry no signature"),
    "cc_static_library": not_native("a static archive"),
    "rust_library": not_native("an `.rlib`, which is not a native binary"),
    "rust_static_library": not_native("a static archive"),
    "swift_library": not_native("a static archive plus Swift module files"),
    "go_library": not_native("a Go archive, which is not an ar archive"),
    "pkg_tar_impl": not_native("a tar archive"),
    "pkg_zip_impl": not_native("a zip archive"),
}

def lookup(kind):
    """The entry for `kind`, or None when the rule is not in the table.

    A rule recorded as `not_native` is *not* the same as an absent one: it
    comes back as a real entry the aspect must still classify with, so that
    every one of its outputs is conclusively marked, not merely left silent
    for an extension to judge afterwards.
    """
    return RULE_KINDS.get(kind)

def is_executable_entry(entry):
    return entry.kind == _EXECUTABLE

def is_all_outputs_entry(entry):
    return entry.kind == _ALL_OUTPUTS

def is_not_native_entry(entry):
    return entry.kind == _NOT_NATIVE

def is_jar_outputs_entry(entry):
    return entry.kind == _JAR_OUTPUTS

def is_forward_entry(entry):
    return entry.kind == _FORWARD

def forwarded_attrs(entry):
    return entry.attrs

def forward_attr_names():
    """Every attribute any row forwards through, for the aspect to propagate."""
    names = {}
    for entry in RULE_KINDS.values():
        for attr_name in entry.attrs:
            names[attr_name] = True
    return sorted(names.keys())

def output_names_are_evidence(entry):
    """Whether this rule's output names may be read as a content hint.

    False for a rule that names its outputs itself, whose names therefore
    describe the rule's own convention rather than the bytes. See `forward`.
    """
    return entry.names_are_evidence
