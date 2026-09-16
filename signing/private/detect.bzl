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

load(
    "//signing/private:binary_kinds.bzl",
    "forward_attr_names",
    "forwarded_attrs",
    "is_all_outputs_entry",
    "is_executable_entry",
    "is_forward_entry",
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
        "formats": "dict of File to format string (`pe` or `macho`).",
    },
)

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

def _aspect_impl(target, ctx):
    # A rule that knows what it builds can say so directly, which is both
    # more accurate than a table row and available to rules this project has
    # never heard of. Returning nothing leaves that provider in place.
    if BinaryFormatInfo in target:
        return []

    entry = lookup(ctx.rule.kind)
    if entry == None:
        return [BinaryFormatInfo(formats = {})]

    formats = {}
    outputs = target[DefaultInfo].files.to_list()

    if is_forward_entry(entry):
        return [BinaryFormatInfo(formats = _forwarded(ctx, entry, outputs))]

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

    return [BinaryFormatInfo(formats = formats)]

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

def binary_formats(target):
    """The `File` to format mapping the aspect attached to `target`.

    Args:
        target: a Target the `binary_format_aspect` was applied to.

    Returns:
        A dict keyed by `File`, holding `PE` or `MACHO`. Files that are not
        native binaries are absent rather than present with an empty value.
    """
    if BinaryFormatInfo not in target:
        return {}
    return target[BinaryFormatInfo].formats
