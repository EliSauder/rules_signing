"""Public API for driving rules_signing from your own rules.

Load this instead of `defs.bzl` when you are writing a rule that produces a
signable artifact itself and needs to sign it as part of its own build, rather
than composing a separate `sign` target after the fact.

Typical use:

```starlark
load(
    "@rules_signing//signing:actions.bzl",
    "SIGNING_ATTRS",
    "SIGNING_TOOLCHAINS",
    "signing_argv",
    "signing_context",
)

def _my_packager_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".exe")

    sctx = signing_context(
        ctx,
        require = ["osslsigncode"],
        require_reason = "the generated installer is always a PE executable",
    )

    # Hand the command to whatever tool does the packaging, so it can sign
    # the artifact in place once it has produced it.
    command = signing_argv(sctx, infile = out)

    ctx.actions.run(
        executable = ctx.executable._packager,
        arguments = [...],
        inputs = depset(transitive = [sctx.inputs]),
        tools = sctx.tools,
        outputs = [out],
        env = sctx.env,
    )

my_packager = rule(
    implementation = _my_packager_impl,
    attrs = dict({...}, **SIGNING_ATTRS),
    toolchains = SIGNING_TOOLCHAINS,
)
```

`signing_argv` also builds command lines that sign an artifact into a separate
output (`outfile`), or that sign many files in one pass (`rel_src_manifest`
together with `out_dir`). For the common "sign these files, keep their
layout" case, call `sign_action` and skip building the command line yourself.
"""

load(
    "//signing/private:action.bzl",
    _SIGNING_ATTRS = "SIGNING_ATTRS",
    _SIGNING_TOOLCHAINS = "SIGNING_TOOLCHAINS",
    _TOOL_KINDS = "TOOL_KINDS",
    _rel_src_manifest = "rel_src_manifest",
    _sign_action = "sign_action",
    _signing_argv = "signing_argv",
    _signing_attrs = "signing_attrs",
    _signing_context = "signing_context",
)

SIGNING_ATTRS = _SIGNING_ATTRS
SIGNING_TOOLCHAINS = _SIGNING_TOOLCHAINS
TOOL_KINDS = _TOOL_KINDS
signing_attrs = _signing_attrs
signing_context = _signing_context
signing_argv = _signing_argv
sign_action = _sign_action
rel_src_manifest = _rel_src_manifest
