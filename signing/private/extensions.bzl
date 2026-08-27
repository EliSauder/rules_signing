load(
    "//signing/toolchains:repositories.bzl",
    "cosign_repo",
    "osslsigncode_repo",
)

def _merge(dst, src):
    for k, v in src.items():
        dst[k] = v

def _add_dep(ctx, tag, nm, deps, dev_deps):
    if (tag.is_root and
        ctx.root_module_has_non_dev_dependency and
        ctx.is_dev_dependency(tag)):
        dev_deps.append(nm)
    elif not tag.is_root and ctx.is_dev_dependency(tag):
        dev_deps.append(nm)
    else:
        dev.append(nm)


def _signing_tools_impl(ctx):
    default_openssl = {
        "name": "signing_openssl",
        "label": Label("@openssl//:openssl"),
        "path": None,
    }

    default_cosign = {
        "name": "signing_cosign",
        "version": "3.1.3",
        "urls": {},
        "sha256": {},
    }

    default_osslsigncode = {
        "name": "signing_osslsigncode",
        "version": "2.14",
        "urls": {},
        "sha256": {},
        "strip_prefix": {},
    }

    seen_cosign = {}
    seen_osslsigncode = {}
    seen_openssl = {}
    has_non_dev_dep = ctx.root_module_has_non_dev_dependency

    for mod in ctx.modules:
        seen_cosign[mod.name] = []
        seen_osslsigncode[mod.name] = []
        seen_openssl[mod.name] = []
        for t in mod.tags.cosign:
            tmp = {"tag": t, "version": None, "urls": [], "sha256": []}
            if t.version:
                tmp["version"] = t.version
            _merge(tmp["urls"], t.urls)
            _merge(tmp["sha256"], t.sha56)
            seen_cosign[mod.name].append(tmp)

        for t in mod.tags.osslsigncode:
            tmp = {"tag": t, "version": None, "urls": [], "sha256":[], "strip_prefix": []}
            if t.version:
                tmp["version"] = t.version
            _merge(tmp["urls"], t.urls)
            _merge(tmp["sha256"], t.sha56)
            _merge(tmp["strip_prefix"], t.strip_prefix)
            seen_osslsigncode[mod.name].append(tmp)

        for t in mod.tags.openssl:
            tmp = {"tag": t, "label": None, "path": None}
            tmp["label"] = t.label
            tmp["path"] = t.path
            seen_openssl[mod.name].append(tmp)

    deps = []
    dev_deps = []

    has_cosign = False
    for name, details in seen_cosign.items():
        has_cosign = True
        nm = "{}_cosign".format(name)
        cosign_repo(
            name = nm,
            version = details["version"],
            urls = details["urls"],
            sha256 = details["sha256"],
        )
        _add_dep(ctx, details["tag"], nm, deps, dev_deps)

    has_osslsigncode = False
    for name, details in seen_osslsigncode.items():
        has_osslsigncode = True
        nm = "{}_osslsigncode".format(name)
        osslsigncode_repo(
            name = nm,
            version = details["version"],
            urls = details["urls"],
            sha256 = details["sha256"],
            strip_prefix = details["strip_prefix"],
        )
        _add_dep(ctx, details["tag"], nm, deps, dev_deps)

    has_openssl = False
    for name, details in seen_openssl.items():
        has_openssl = True
        nm = "{}_openssl".format(name)
        if details["path"]:
            openssl_local_repo(
                name = nm,
                path = details["path"],
            )
        else:
            openssl_label_repo(
                name = nm,
                label = details["label"],
            )

        _add_dep(ctx, details["tag"], nm, deps, dev_deps)

    if not has_cosign:
        cosign_repo(
            name = default_cosign["name"],
            version = default_cosign["version"],
            urls = default_cosign["urls"],
            sha256 = default_cosign["sha256"],
        )
        deps.append(default_cosign["name"])

    if not has_osslsigncode:
        osslsigncode_repo(
            name = default_osslsigncode["name"],
            version = default_osslsigncode["version"],
            urls = default_osslsigncode["urls"],
            sha256 = default_osslsigncode["sha256"],
            strip_prefix = default_osslsigncode["strip_prefix"],
        )
        deps.append(default_osslsigncode["name"])

    if not has_openssl:
        openssl_repo(
            name = default_openssl["name"],
            path = default_openssl["path"],
            label = default_openssl["label"],
        )
        deps.append(default_openssl["name"])

    return ctx.extension_metadata(
        root_module_direct_deps = deps,
        root_module_direct_dev_deps = dev_deps,
    )


_cosign_tag = tag_class(attrs = {
    "version": attr.string(),
    "urls": attr.string_dict(doc = "host_key -> URL override."),
    "sha256": attr.string_dict(doc = "host_key -> sha256."),
})

_osslsigncode_tag = tag_class(attrs = {
    "version": attr.string(),
    "urls": attr.string_dict(doc = "host_key -> URL override."),
    "sha256": attr.string_dict(doc = "host_key -> sha256."),
    "strip_prefix": attr.string_dict(doc = "host_key -> strip_prefix."),
})

_openssl_tag = tag_class(attrs = {
    "path": attr.string(),
    "label": attr.label(
        default = "@openssl//:openssl",
        executable = True,
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
