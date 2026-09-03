load(
    "//signing/toolchains:repositories.bzl",
    "cosign_repo",
    "openssl_label_repo",
    "openssl_local_repo",
    "osslsigncode_repo",
)

def _add_dep(ctx, tag, name, deps, dev_deps):
    if ctx.is_dev_dependency(tag):
        dev_deps.append(name)
    else:
        deps.append(name)

def _repo_name(mod, tool):
    """Names the repository a tool tag creates.

    The root module gets the plain `signing_<tool>` name, which is also what
    the untagged defaults below are called, so a tool is imported the same way
    whether or not it was configured:

        use_repo(signing_tools, "signing_openssl")

    Only one repository can hold that name, so additional tags and tags from
    non-root modules fall back to a qualified form. In practice those are rare:
    a tag selects a tool version or location, which is a decision for the
    module actually doing the signing.
    """

    if mod.is_root:
        return "signing_" + tool
    return "{}_{}".format(mod.name, tool)

def _signing_tools_impl(ctx):
    deps = []
    dev_deps = []

    # Only the root module's tags replace a default. A tag elsewhere in the
    # graph creates its own repository and leaves `signing_<tool>` alone, so it
    # cannot pull the default out from under the root module.
    root_cosign = False
    root_osslsigncode = False

    for mod in ctx.modules:
        for i, t in enumerate(mod.tags.cosign):
            root_cosign = root_cosign or mod.is_root
            name = _repo_name(mod, "cosign")
            cosign_repo(
                name = name,
                version = t.version if t.version else "3.1.3",
                urls = t.urls,
                sha256 = t.sha256,
            )
            _add_dep(ctx, t, name, deps, dev_deps)

        for i, t in enumerate(mod.tags.osslsigncode):
            root_osslsigncode = root_osslsigncode or mod.is_root
            name = _repo_name(mod, "osslsigncode")
            osslsigncode_repo(
                name = name,
                version = t.version if t.version else "2.14",
                urls = t.urls,
                sha256 = t.sha256,
                strip_prefix = t.strip_prefix,
            )
            _add_dep(ctx, t, name, deps, dev_deps)

        for i, t in enumerate(mod.tags.openssl):
            name = _repo_name(mod, "openssl")
            if t.path:
                openssl_local_repo(
                    name = name,
                    path = t.path,
                )
            elif t.label:
                openssl_label_repo(
                    name = name,
                    label = t.label,
                )
            else:
                fail("signing_tools.openssl() needs either `path` (to " +
                     "adopt a host binary) or `label` (a target built by " +
                     "another module).")
            _add_dep(ctx, t, name, deps, dev_deps)

    if not root_cosign:
        cosign_repo(name = "signing_cosign", version = "3.1.3")
        deps.append("signing_cosign")

    if not root_osslsigncode:
        osslsigncode_repo(name = "signing_osslsigncode", version = "2.14")
        deps.append("signing_osslsigncode")

    # openssl deliberately has no default. cosign and osslsigncode are always
    # useful, but openssl is needed only to convert PKCS#12 material to PEM,
    # and defaulting it would force every consumer to depend on the openssl
    # module (which builds from source) for a conversion most never perform.
    # `signing_tools.openssl()` therefore both opts in and names the repo.

    if ctx.root_module_has_non_dev_dependency and len(deps) > 0:
        return ctx.extension_metadata(
            root_module_direct_deps = deps,
            root_module_direct_dev_deps = dev_deps,
        )
    else:
        return ctx.extension_metadata(
            root_module_direct_deps = [],
            root_module_direct_dev_deps = dev_deps + deps,
        )

_cosign_tag = tag_class(attrs = {
    "version": attr.string(),
    "urls": attr.string_dict(doc = "host_key -> URL override."),
    "sha256": attr.string_dict(doc = "host_key -> sha256 override."),
})

_osslsigncode_tag = tag_class(attrs = {
    "version": attr.string(),
    "urls": attr.string_dict(doc = "host_key -> URL override."),
    "sha256": attr.string_dict(doc = "host_key -> sha256 override."),
    "strip_prefix": attr.string_dict(doc = "host_key -> strip_prefix override."),
})

_openssl_tag = tag_class(attrs = {
    "path": attr.string(
        doc = "Path to an openssl binary already installed on the host, " +
              "or a bare program name to resolve against PATH. Takes " +
              "precedence over `label`.",
    ),
    "label": attr.label(
        doc = "Target providing an openssl binary, built by another " +
              "module. Only resolved when `path` is unset, so callers who " +
              "adopt a host binary never need to depend on that module.",
    ),
})

signing_tools = module_extension(
    implementation = _signing_tools_impl,
    tag_classes = {
        "cosign": _cosign_tag,
        "osslsigncode": _osslsigncode_tag,
        "openssl": _openssl_tag,
    },
)
