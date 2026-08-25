load(
    "//signing/toolchains:repositories.bzl",
    "cosign_repo",
    "osslsigncode_repo",
)

def _merge(dst, src):
    for k, v in src.items():
        dst[k] = v

def _signing_tools_impl(ctx):

    opensslcfg = {
        "label": None,
        "path": None,
    }

    cosigncfg = {
        "version": "3.1.3",
        "urls": {},
        "sha256": {},
    }

    osslsigncode = {
        "version": "2.14",
        "urls": {},
        "sha256": {},
        "strip_prefix": {},
    }

    for mod in ctx.modules:
        for t in mod.tags.cosign:
            if t.version:
                cosigncfg["version"] = t.version
            _merge(cosigncfg["urls"], t.urls)
            _merge(cosigncfg["sha256"], t.sha56)

        for t in mod.tags.osslsigncode:
            if t.version:
                cosigncfg["version"] = t.version
            _merge(cosigncfg["urls"], t.urls)
            _merge(cosigncfg["sha256"], t.sha56)
            _merge(cosigncfg["strip_prefix"], t.strip_prefix)

        for t in mod.tags.openssl:
            opensslcfg["label"] = t.label
            opensslcfg["path"] = t.path

    deps = []

    cosign_repo(
        name = "signing_cosign",
        version = cosigncfg["version"],
        urls = cosigncfg["urls"],
        sha256 = cosigncfg["sha256"],
    )
    deps.append("signing_cosign")

    osslsigncode_repo(
        name = "signing_osslsigncode",
        version = cosigncfg["version"],
        urls = cosigncfg["urls"],
        sha256 = cosigncfg["sha256"],
        strip_prefix = cosigncfg["strip_prefix"],
    )
    deps.append("signing_osslsigncode")

    if opensslcfg["path"]:
        openssl_local_repo(
            name = "signing_openssl",
            path = opensslcfg["path"],
        )
    else:
        openssl_label_repo(
            name = "signing_openssl",
            label = opensslcfg["label"],
        )
    deps.append("signing_openssl")

    return ctx.extension_metadata(
        root_module_direct_deps = deps,
        root_module_direct_dev_deps = [],
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
