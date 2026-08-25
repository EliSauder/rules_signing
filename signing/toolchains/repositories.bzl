load("//toolchains:versions.bzl", "COSIGN_VERSIONS", "OSSLSIGNCODE_VERSIONS")

_COSIGN_ASSET = {
    "linux_amd64": "cosign-linux-amd64",
    "linux_arm64": "cosign-linux-arm64",
    "linux_arm": "cosign-linux-arm",
    "darwin_amd64": "cosign-darwin-amd64",
    "darwin_arm64": "cosign-darwin-arm64",
    "windows_amd64": "cosign-windows-amd64.exe",
}
_COSIGN_BASE_URL = "https://github.com/sigstore/cosign/releases/download/v{v}/{a}"

_OSSLSIGNCODE_ASSET = {
    "linux_amd64": "osslsigncode-{v}-linux-amd64.tar.gz",
    "linux_arm64": "osslsigncode-{v}-linux-arm64.tar.gz",
    "darwin_amd64": "osslsigncode-{v}-darwin-amd64.zip",
    "darwin_arm64": "osslsigncode-{v}-darwin-arm64.zip",
    "windows_amd64": "osslsigncode-{v}-windows-amd64.zip",
    "windows_arm64": "osslsigncode-{v}-windows-arm64.zip",
}
_OSSLSIGNCODE_BASE_URL = "https://github.com/EliSauder/osslsigncode/releases/download/{v}/{a}"

def _define_download_tool(ctx, name, url, sha256, windows, build):
    ext = ".exe" if windows else ""
    out = "bin/{}{}".format(name, ext)
    ctx.download(
        url = url,
        output = out
        executable = True,
        sha256 = sha256,
    )
    build.append(
        'native_binary(name = "{n}", src = "{s}", out = "{n}{e}")'.format(
            n = name,
            s = out,
            e = ext or ".run",
        )
    )

def _define_download_and_extract_tool(ctx, name, url, sha256, strip_prefix, windows, build):
    ext = ".exe" if windows else ""
    out = "bin/{}{}".format(name, ext)
    ctx.download_and_extract(
        url = url,
        output = out
        executable = True,
        sha256 = sha256,
        strip_prefix = strip_prefix,
    )
    build.append(
        'native_binary(name = "{n}", src = "{s}", out = "{n}{e}")'.format(
            n = name,
            s = out,
            e = ext or ".run",
        )
    )

def _host_platform(ctx):
    os = ctx.os.name.lower()
    arch = ctx.os.arch.lower()
    if os.startswith("mac") or os.startswith("darwin"):
        os_key = "darwin"
    elif os.startswith("win"):
        os_key = "windows"
    else:
        os_key = "linux"

    if arch in ("aarch64", "arm64"):
        arch_key = "arm64"
    elif arch in ("x86_64", "amd64", "x64"):
        arch_key = "amd64"
    elif arch in("arm", "aarch32"):
        arch_key = "arm"
    else:
        arch_key = arch
    return os_key, arch_key

def _cosign_repo_impl(ctx):
    os_key, arch_key = _host_platform(ctx)
    host = "{}_{}".format(os_key, arch_key)
    windows = os_key == "windows"

    build = [
        'load("@bazel_skylib//rules:native_binary.bzl", "native_binary")',
        'package(default_visibility = ["//visibility:public"])',
        "",
    ]

    url = ctx.attr.urls.get(host, "")
    sha = ctx.attr.sha256.get(host, "")
    version = ctx.attr.version
    if not url and host in _COSIGN_ASSET:
        asset = _COSIGN_ASSET[host]
        verstr = "{}/{}".format(version, asset)
        if not verstr in COSIGN_VERSIONS:
            fail("{} does not have a known sha for version {} on host {}".format(asset, version, host))
        sha = COSIGN_VERSIONS[verstr]
        sha = sha.removeprefix("sha:")

        url = _COSIGN_BASE_URL.format(v = version, a = asset)

    if url:
        _define_download_tool(
            ctx,
            "cosign",
            url,
            sha,
            windows,
            build,
        )
    else:
        fail("no cosign download available for this platform")

    ctx.file("BUILD.bazel", "\n".join(build) + "\n")

cosign_repo = repository_rule(
    implementation = _cosign_repo_impl,
    doc = "Defines repository rools for acquiring the cosign tool.",
    attrs = {
        "version": attr.string(default = "3.1.3"),
        "urls": attr.string_dict(
            default = {},
            doc = "Optional host_key -> URL overrides (host_key like 'linux_amd64').",
        ),
        "sha256": attr.string_dict(
            default = {},
            doc = "Optional host_key -> sha256.",
        ),
    },
)

def _osslsigncode_repo_impl(ctx):
    os_key, arch_key = _host_platform(ctx)
    host = "{}_{}".format(os_key, arch_key)
    windows = os_key == "windows"

    build = [
        'load("@bazel_skylib//rules:native_binary.bzl", "native_binary")',
        'package(default_visibility = ["//visibility:public"])',
        "",
    ]

    url = ctx.attr.urls.get(host, "")
    sha = ctx.attr.sha256.get(host, "")
    version = ctx.attr.version
    stripprefix = ctx.attr.strip_prefix.get(host, "")

    if not url and host in _OSSLSIGNCODE_ASSET:
        asset = _OSSLSIGNCODE_ASSET[host].format(v = version)
        verstr = "{}/{}".format(version, asset)
        if verstr not in OSSLsigncode_VERSIONS:
            fail("{} does not have a knowh sha for version {} on host {}".format(asset, version, host))

        sha = OSSLSIGNCODE_VERSIONS[verstr]
        sha = sha.removeprefix("sha256:")
        url = _OSSLSIGNCODE_BASE_URL.format(v = version, a = asset)

        stripprefix = ".".join(asset.split(".")[:-1])
        stripprefix = stripprefix.removesuffix(".tar")

    if url:
        _define_download_and_extract_tool(
            ctx,
            "osslsigncode",
            url,
            sha,
            stripprefix,
            windows,
            build,
        )
    else:
        fail("no osslsigncode download available for this platform")


    ctx.file("BUILD.bazel", "\n".join(build) + "\n")


osslsigncode_repo = repository_rule(
    implementation = _osslsigncode_repo_impl,
    doc = "Defines repository for acquiring the osslsigncode tool source.",
    attrs = {
        "version": attr.string(default = "2.14"),
        "urls": attr.string_dict(
            default = {},
            doc = "Optional host_key -> URL overrides (host_key like 'linux_amd64').",
        ),
        "sha256": attr.string_dict(
            default = {},
            doc = "Optional host_key -> sha256.",
        ),
        "strip_prefix": attr.string_dict(
            default = {},
            doc = "Optional host_key -> strip_prefix",
        ),
    },
)

def _openssl_local_impl(ctx):
    binpath = ctx.path(ctx.attr.path)
    if not binpath.exists:
        fail("openssl path provided does not exist")

    ctx.symlink(binpath, binpath.basename)

    ctx.file("BUILD.bazel", "\n".join([
        'load("@bazel_skylib//rules:native_binary.bzl", "native_binary")',
        'package(default_visibility = ["//visibility:public"])',
        'native_binary(name = "{n}", src = "{s}", out = "{n}{e}")'.format(
            n = "openssl",
            s = binpath.basename,
            e = ".run",
        )
    ]))

openssl_local_repo = repository_rule(
    implementation = _openssl_local_impl,
    attrs = {
        "path": attr.string(
            mandatory = True,
        ),
    },
)

def _openssl_label_impl(ctx):
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'alias(name = "{n}", actual = "{s}")'.format(
            n = "openssl",
            s = ctx.attr.label,
        )
    ]))

openssl_label_repo = repository_rule(
    implementation = _openssl_local_impl,
    attrs = {
        "label": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
)
