"""Works out, while the build graph is built, which files are native binaries.

Signing has to know what a file *is* before it exists: the outputs of a rule
are declared during analysis, and a detached signature is extra files, so
"which signer" and "which outputs" are the same question and both have to be
answered up front.

Reading the file is not an option at that point -- it has not been built yet.
What analysis does have is the rule that will build it and the configuration
it will be built in, and between them those give a better answer than the
bytes would:

  * whether a file is a native binary at all comes from its producing rule,
    via the table in `binary_kinds.bzl`. A `cc_binary` produces one; a
    `py_binary` produces a launcher script that merely looks like one.

  * which *kind* of native binary comes from the configuration. A binary is
    PE because it was built for Windows, not because it happens to start with
    `MZ`, and the configuration says so exactly.

This aspect runs over the signed target's dependencies, so each one is
inspected in its own configuration. That is what makes a cross-compiled
binary readable: a `cc_binary` transitioned to Windows reports PE even though
the target doing the signing is configured for something else.

A rule is not limited to what the table can express. Any rule may return a
`BinaryFormatInfo` of its own, which the aspect leaves alone -- the right
answer for a rule whose outputs this project could not describe from the
outside, and the only one available to a rule it has never heard of.
"""

load("@bazel_lib//lib:glob_match.bzl", "glob_match")
load(
    "//signing/private:binary_kinds.bzl",
    "default_globs",
    "forward_attr_names",
    "forwarded_attrs",
    "is_all_outputs_entry",
    "is_executable_entry",
    "is_forward_entry",
    "is_jar_outputs_entry",
    "is_not_native_entry",
    "MACHO",
    "NOT_NATIVE",
    "PE",
    "lookup",
    "output_names_are_evidence",
)

# PE, MACHO and NOT_NATIVE are defined in binary_kinds.bzl and loaded above;
# import them from there rather than from this file.

BinaryFormatInfo = provider(
    doc = "Maps each of a target's Files to the native binary format it will " +
          "be built as, for the files that are native binaries at all.",
    fields = {
        "formats": "dict of File to format string (`pe`, `macho` or `jar`).",
        "unsigned": "Optional. dict of File to True for the outputs the " +
                    "producing rule's default `include`/`exclude` leave " +
                    "unsigned. `sign` copies them through unless " +
                    "`use_rule_defaults = False`.",
    },
)

def _unsigned_of(info):
    # Optional, so a rule returning its own provider need not set it.
    return getattr(info, "unsigned", None) or {}

def _platform_format(ctx):
    """The native binary format of the configuration being analysed."""
    if ctx.target_platform_has_constraint(
        ctx.attr._windows_constraint[platform_common.ConstraintValueInfo],
    ):
        return PE
    if ctx.target_platform_has_constraint(
        ctx.attr._macos_constraint[platform_common.ConstraintValueInfo],
    ):
        return MACHO

    # Every other platform's executables have no signature format of their
    # own, so there is nothing for a native signer to do with them.
    return None

def _forwarded_formats(ctx, entry):
    """Formats inherited from the targets a pass-through rule copies from."""
    formats = {}
    for attr_name in forwarded_attrs(entry):
        dep = getattr(ctx.rule.attr, attr_name, None)
        if dep == None:
            continue
        for target in (dep if type(dep) == "list" else [dep]):
            if type(target) == "Target" and BinaryFormatInfo in target:
                formats.update(target[BinaryFormatInfo].formats)
    return formats

def _forwarded(ctx, entry, outputs):
    """Carries classifications across a rule that passes bytes through.

    Matched two ways, because pass-through rules come in two shapes. A
    grouping rule re-reports the very `File`s it was given, so those match by
    identity -- which is exact, and holds however many unclassified files are
    grouped alongside. A copying rule produces new `File`s instead, and
    nothing in analysis links a copy back to its original, so what is left
    over is paired up in order.

    Pairing in order is only sound when nothing was added or dropped, so it
    is used only if the counts agree. A rule doing more than it was recorded
    as doing fails that test, and guessing which output came from which input
    would be worse than declining to classify.
    """
    inherited = _forwarded_formats(ctx, entry)

    formats = {}
    unmatched_outputs = []
    for f in outputs:
        if f in inherited:
            formats[f] = inherited[f]
        else:
            unmatched_outputs.append(f)

    leftover = [fmt for f, fmt in inherited.items() if f not in formats]
    if len(leftover) == len(unmatched_outputs):
        for i in range(len(unmatched_outputs)):
            formats[unmatched_outputs[i]] = leftover[i]
    elif not output_names_are_evidence(entry):
        # This rule names its own outputs, so those names are not evidence of
        # anything. Recording a verdict keeps them from being judged by
        # extension. Nothing here changes a name; only how one is read.
        for f in unmatched_outputs:
            formats[f] = NOT_NATIVE

    return formats

def _inherited_unsigned(ctx, entry, outputs):
    """Unsigned outputs carried across a pass-through rule, as for formats.

    Matched by `File` identity, and failing that paired in order when the
    rule produced exactly as many files as it was given.
    """
    inherited = {}
    sources = []
    for attr_name in forwarded_attrs(entry):
        dep = getattr(ctx.rule.attr, attr_name, None)
        if dep == None:
            continue
        for target in (dep if type(dep) == "list" else [dep]):
            if type(target) != "Target":
                continue
            if BinaryFormatInfo in target:
                inherited.update(_unsigned_of(target[BinaryFormatInfo]))
            if DefaultInfo in target:
                sources.extend(target[DefaultInfo].files.to_list())
    if not inherited:
        return {}

    paired = len(sources) == len(outputs)
    unsigned = {}
    for i in range(len(outputs)):
        f = outputs[i]
        if f in inherited or (paired and sources[i] in inherited):
            unsigned[f] = True
    return unsigned

def _matches(patterns, f):
    for pattern in patterns:
        if glob_match(pattern, f.short_path):
            return True
    return False

def _default_unsigned(entry, outputs):
    """The outputs a row's own default globs leave unsigned."""
    include, exclude = default_globs(entry)
    return {
        f: True
        for f in outputs
        if (include and not _matches(include, f)) or _matches(exclude, f)
    }

def _aspect_impl(target, ctx):
    # A rule that knows what it builds can say so directly, which is both
    # more accurate than a table row and available to rules this project has
    # never heard of. Returning nothing leaves that provider in place.
    if BinaryFormatInfo in target:
        return []

    entry = lookup(ctx.rule.kind)
    if entry == None:
        return [BinaryFormatInfo(formats = {}, unsigned = {})]

    outputs = target[DefaultInfo].files.to_list()
    unsigned = _default_unsigned(entry, outputs)
    if is_forward_entry(entry):
        unsigned.update(_inherited_unsigned(ctx, entry, outputs))
    return [BinaryFormatInfo(
        formats = _classify(target, ctx, entry, outputs),
        unsigned = unsigned,
    )]

def _classify(target, ctx, entry, outputs):
    """The `File` to format mapping for a rule the table has a row for."""
    formats = {}

    if is_forward_entry(entry):
        return _forwarded(ctx, entry, outputs)

    if is_not_native_entry(entry):
        # Conclusive for every output, not just the executable: a rule like
        # `sh_binary` can report a Windows launcher named `<name>.exe`
        # alongside outputs an extension check would read correctly on its
        # own, and the whole set has to be marked so none of them falls
        # through to being judged by name.
        for f in outputs:
            formats[f] = NOT_NATIVE
        return formats

    fmt = entry.format if entry.format else _platform_format(ctx)

    # A rule in the table speaks for its outputs either way. Where the
    # configuration has no native format -- an ELF, most often -- the answer
    # is "not a native binary", which is a verdict and not a silence, and it
    # is what stops a misleading name being consulted afterwards.
    verdict = fmt if fmt else NOT_NATIVE

    if is_executable_entry(entry):
        files_to_run = target[DefaultInfo].files_to_run
        if files_to_run != None and files_to_run.executable != None:
            formats[files_to_run.executable] = verdict
    elif is_all_outputs_entry(entry):
        for f in outputs:
            formats[f] = verdict
    elif is_jar_outputs_entry(entry):
        # Only the `.jar` files are jarsigner-signable, but the rest of the
        # rule's outputs still get a verdict rather than being left silent.
        # A launcher stub or `.jdeps` beside the jar is conclusively not a
        # native binary, and saying so is what stops the `<name>.exe` stub
        # `scala_binary` reports on Windows from being read by that name
        # afterwards and handed to osslsigncode, which would corrupt it.
        for f in outputs:
            formats[f] = verdict if f.extension == "jar" else NOT_NATIVE

    return formats

binary_format_aspect = aspect(
    implementation = _aspect_impl,
    doc = "Classifies a dependency's outputs as native binaries, in that " +
          "dependency's own configuration.",

    # Only the attributes some row forwards through. Propagating further
    # would visit the whole graph below the signed target to no purpose,
    # since a rule's own outputs are classified from the rule itself.
    attr_aspects = forward_attr_names(),
    attrs = {
        "_windows_constraint": attr.label(default = "@platforms//os:windows"),
        "_macos_constraint": attr.label(default = "@platforms//os:macos"),
    },
)

def rule_default_unsigned(target):
    """The `File`s the producing rules' default globs leave unsigned.

    Args:
        target: a Target the `binary_format_aspect` was applied to.

    Returns:
        A dict keyed by `File`; see `BinaryFormatInfo.unsigned`.
    """
    if BinaryFormatInfo not in target:
        return {}
    return _unsigned_of(target[BinaryFormatInfo])

def binary_formats(target):
    """The `File` to format mapping the aspect attached to `target`.

    Args:
        target: a Target the `binary_format_aspect` was applied to.

    Returns:
        A dict keyed by `File`, holding `PE`, `MACHO` or `JAR`. Files that are not
        native binaries are absent rather than present with an empty value.
    """
    if BinaryFormatInfo not in target:
        return {}
    return target[BinaryFormatInfo].formats
