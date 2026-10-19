load("@bazel_lib//lib:glob_match.bzl", "glob_match")
load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")
load(
    "//signing/private:action.bzl",
    "SIGNING_TOOLCHAINS",
    "sign_action",
    "signed_outputs",
    "signing_attrs",
)
load(
    "//signing/private:detect.bzl",
    "binary_format_aspect",
    "binary_formats",
    "rule_default_unsigned",
)

def _sign_impl(ctx):
    srcs = ctx.attr.src[DefaultInfo].files.to_list()

    # Which sources are native binaries, and of what format, as reported by
    # the rules that build them. Decided here so that the signer, the
    # toolchains asked for and the declared outputs are all derived from one
    # answer rather than three that could disagree.
    formats = binary_formats(ctx.attr.src)

    def matches(patterns, f):
        return [p for p in patterns if glob_match(p, f.short_path)]

    # The producing rules' default globs, from their rows in the table, add
    # to this target's own: a file either leaves unsigned stays unsigned.
    rule_unsigned = rule_default_unsigned(ctx.attr.src) if ctx.attr.use_rule_defaults else {}
    unsigned = [
        f
        for f in srcs
        if f in rule_unsigned or
           (ctx.attr.include and not matches(ctx.attr.include, f)) or
           matches(ctx.attr.exclude, f)
    ]

    outs = signed_outputs(
        ctx,
        srcs = srcs,
        out_name = ctx.attr.out if ctx.attr.out else None,
        formats = formats,
        attr_prefix = "",
        unsigned = unsigned,
    )

    if srcs:
        sign_action(
            ctx,
            srcs = srcs,
            outs = outs,
            formats = formats,
            attr_prefix = "",
        )

    return [DefaultInfo(
        files = depset(outs.files),
        runfiles = ctx.attr.src[DefaultInfo].default_runfiles.merge(
            ctx.runfiles(files = outs.files),
        ),
    )]

sign = rule(
    implementation = _sign_impl,
    doc = "Signs all files from `src`, preserving relative output structure. " +
          "Each source keeps its own shape: a file is signed into a file and " +
          "a directory into a directory, both under their source-relative " +
          "path. Sources signed with a detached signature (cosign) are " +
          "accompanied by their `.sig` and `.bundle.json` files, which " +
          "`detached_signatures` can extend to every source or turn off " +
          "entirely.",
    attrs = dict({
        "src": attr.label(
            mandatory = True,
            providers = [[DefaultInfo]],
            aspects = [binary_format_aspect],
            cfg = "target",
        ),
        "out": attr.string(
            doc = "Optional name of the directory the signed outputs are " +
                  "placed under, relative to the package. Defaults to " +
                  "`<name>.signed`. The directory itself is not an output; " +
                  "the files inside it are.",
        ),
        "include": attr.string_list(
            doc = "Globs over source paths (`short_path`, `**` crossing " +
                  "directories). When set, only matching sources are signed; " +
                  "the rest are copied through unsigned.",
        ),
        "exclude": attr.string_list(
            doc = "Globs over source paths. Matching sources are copied " +
                  "through unsigned, with no detached signature either, " +
                  "whatever `tool` or `detached_signatures` say. Wins over " +
                  "`include`. A directory artifact is matched as a whole.",
        ),
        "use_rule_defaults": attr.bool(
            default = True,
            doc = "Whether to also leave unsigned what the producing rules' " +
                  "default `include`/`exclude` globs do, such as " +
                  "`publish_binary`'s `runtimes/` natives. Merged with this " +
                  "target's own globs; set False to use only those.",
        ),
        # Unprefixed: `sign` owns its whole attribute surface, so there is
        # nothing here for the signing options to collide with, and these
        # names are this rule's published API.
    }, **dict(signing_attrs(prefix = ""), **STAMP_ATTRS)),
    toolchains = SIGNING_TOOLCHAINS,
)
