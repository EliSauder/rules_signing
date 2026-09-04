load("@bazel_lib//lib:stamping.bzl", "STAMP_ATTRS")
load(
    "//signing/private:action.bzl",
    "SIGNING_TOOLCHAINS",
    "sign_action",
    "signing_attrs",
)

def _sign_impl(ctx):
    srcs = ctx.attr.src[DefaultInfo].files.to_list()
    out_name = ctx.attr.out if ctx.attr.out else "{}.signed".format(ctx.label.name)
    out_dir = ctx.actions.declare_directory(out_name)

    sign_action(ctx, srcs = srcs, out_dir = out_dir, attr_prefix = "")

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
        # Unprefixed: `sign` owns its whole attribute surface, so there is
        # nothing here for the signing options to collide with, and these
        # names are this rule's published API.
    }, **dict(signing_attrs(prefix = ""), **STAMP_ATTRS)),
    toolchains = SIGNING_TOOLCHAINS,
)
