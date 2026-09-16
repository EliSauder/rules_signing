load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")
load(
    "//signing/private:action.bzl",
    "SIGNING_TOOLCHAINS",
    "sign_action",
    "signed_outputs",
    "signing_attrs",
)

def _sign_impl(ctx):
    srcs = ctx.attr.src[DefaultInfo].files.to_list()
    outs = signed_outputs(
        ctx,
        srcs = srcs,
        out_name = ctx.attr.out if ctx.attr.out else None,
        attr_prefix = "",
    )

    if srcs:
        sign_action(ctx, srcs = srcs, outs = outs, attr_prefix = "")

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
            cfg = "target",
        ),
        "out": attr.string(
            doc = "Optional name of the directory the signed outputs are " +
                  "placed under, relative to the package. Defaults to " +
                  "`<name>.signed`. The directory itself is not an output; " +
                  "the files inside it are.",
        ),
        # Unprefixed: `sign` owns its whole attribute surface, so there is
        # nothing here for the signing options to collide with, and these
        # names are this rule's published API.
    }, **dict(signing_attrs(prefix = ""), **STAMP_ATTRS)),
    toolchains = SIGNING_TOOLCHAINS,
)
