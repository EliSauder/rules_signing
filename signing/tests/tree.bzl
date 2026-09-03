"""Test-only helper that materializes a directory (tree) artifact.

The `sign` rule treats directory artifacts specially: their contents are
unknown at analysis time, so signing tools are dispatched per file at
execution time. These fixtures exercise that path end to end.
"""

def _make_tree_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)

    out_q = "'" + out.path.replace("'", "'\"'\"'") + "'"
    commands = ["mkdir -p {}".format(out_q)]
    for relative_path, content in ctx.attr.files.items():
        target = "{}/{}".format(out.path, relative_path)
        target_q = "'" + target.replace("'", "'\"'\"'") + "'"
        commands.append("mkdir -p \"$(dirname {})\"".format(target_q))
        commands.append("printf '%s' {} > {}".format(repr(content), target_q))

    ctx.actions.run_shell(
        outputs = [out],
        command = " && ".join(commands),
        mnemonic = "MakeTestTree",
    )
    return [DefaultInfo(files = depset([out]))]

make_tree = rule(
    implementation = _make_tree_impl,
    attrs = {
        "files": attr.string_dict(
            mandatory = True,
            doc = "Mapping of tree-relative path to file content.",
        ),
    },
    doc = "Produces a directory artifact populated with the given files.",
)
