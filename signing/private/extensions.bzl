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

def _signing_tools_impl(ctx):
    deps = []
    dev_deps = []

    saw_cosign = False
    saw_osslsigncode = False
    saw_openssl = False

    for mod in ctx.modules:
        for i, t in enumerate(mod.tags.cosign):
            saw_cosign = True
            name = "{}_cosign_{}".format(mod.name, i)
            cosign_repo(
                name = name,
                version = t.version if t.version else "3.1.3",
                urls = t.urls,
                sha256 = t.sha256,
            )
            _add_dep(ctx, t, name, deps, dev_deps)

        for i, t in enumerate(mod.tags.osslsigncode):
            saw_osslsigncode = True
            name = "{}_osslsigncode_{}".format(mod.name, i)
            osslsigncode_repo(
                name = name,
                version = t.version if t.version else "2.14",
                urls = t.urls,
                sha256 = t.sha256,
                strip_prefix = t.strip_prefix,
            )
            _add_dep(ctx, t, name, deps, dev_deps)

        for i, t in enumerate(mod.tags.openssl):
            saw_openssl = True
            name = "{}_openssl_{}".format(mod.name, i)
            if t.path:
                openssl_local_repo(
                    name = name,
                    path = t.path,
                )
            else:
                openssl_label_repo(
                    name = name,
                    label = t.label,
                )
            _add_dep(ctx, t, name, deps, dev_deps)

    if not saw_cosign:
        cosign_repo(name = "signing_cosign", version = "3.1.3")
        deps.append("signing_cosign")

    if not saw_osslsigncode:
        osslsigncode_repo(name = "signing_osslsigncode", version = "2.14")
        deps.append("signing_osslsigncode")

    if not saw_openssl:
        openssl_label_repo(name = "signing_openssl", label = Label("@openssl//:openssl"))
        deps.append("signing_openssl")

    return ctx.extension_metadata(
        root_module_direct_deps = deps,
        root_module_direct_dev_deps = dev_deps,
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
    "path": attr.string(),
    "label": attr.label(
        default = "@openssl//:openssl",
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
