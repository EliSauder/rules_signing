"""Test-only helper that records a target's file names in a manifest.

Tests that check `sign` does not mangle file names need the list of expected
names, but they cannot receive it through `args`: Bazel applies shell
tokenization there, so a name containing a space would arrive as two
arguments. Deliberately awkward names are the whole point of those fixtures.

Writing the names to a file instead sidesteps both that tokenization and any
shell quoting, and keeps the expectations derived from the sources rather than
duplicated in the test.
"""

def _file_name_manifest_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".txt")
    paths = []
    for target in ctx.attr.srcs:
        for f in target[DefaultInfo].files.to_list():
            paths.append(f.short_path)

    # ctx.actions.write takes the content directly, so no name ever reaches a
    # shell. Sorted for a stable, reproducible output.
    ctx.actions.write(out, "".join([p + "\n" for p in sorted(paths)]))
    return [DefaultInfo(files = depset([out]))]

file_name_manifest = rule(
    implementation = _file_name_manifest_impl,
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            allow_files = True,
            doc = "Targets whose files' short_paths are recorded.",
        ),
    },
    doc = "Writes one file short_path per line, for tests to read as expectations.",
)
