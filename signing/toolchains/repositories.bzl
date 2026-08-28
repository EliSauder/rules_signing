load("//signing/toolchains:versions.bzl", "COSIGN_VERSIONS", "OSSLSIGNCODE_VERSIONS")

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

def _trim_sha256_prefix(sha):
    if sha.startswith("sha256:"):
        return sha[7:]
    return sha

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
    elif arch in ("arm", "aarch32"):
        arch_key = "arm"
    else:
        arch_key = arch

    return "{}_{}".format(os_key, arch_key), os_key == "windows"

def _emit_filegroup_build(name, src):
    return "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'filegroup(name = "{n}_file", srcs = ["{s}"])'.format(n = name, s = src),
        "",
    ])

def _cosign_repo_impl(ctx):
    host, windows = _host_platform(ctx)
    version = ctx.attr.version
    url = ctx.attr.urls.get(host, "")
    sha = ctx.attr.sha256.get(host, "")

    if not url:
        asset = _COSIGN_ASSET.get(host)
        if not asset:
            fail("no cosign asset mapping for host '{}'".format(host))
        key = "v{}/{}".format(version, asset)
        if key not in COSIGN_VERSIONS:
            fail("no known cosign sha256 for '{}'".format(key))
        sha = _trim_sha256_prefix(COSIGN_VERSIONS[key])
        url = _COSIGN_BASE_URL.format(v = version, a = asset)

    ext = ".exe" if windows else ""
    out = "cosign{}".format(ext)
    ctx.download(
        url = url,
        output = out,
        executable = True,
        sha256 = _trim_sha256_prefix(sha),
    )
    ctx.file("BUILD.bazel", _emit_filegroup_build("cosign", out))

cosign_repo = repository_rule(
    implementation = _cosign_repo_impl,
    doc = "Repository rule that downloads cosign for the host platform.",
    attrs = {
        "version": attr.string(default = "3.1.3"),
        "urls": attr.string_dict(default = {}),
        "sha256": attr.string_dict(default = {}),
    },
)

def _osslsigncode_repo_impl(ctx):
    host, windows = _host_platform(ctx)
    version = ctx.attr.version
    url = ctx.attr.urls.get(host, "")
    sha = ctx.attr.sha256.get(host, "")
    strip_prefix = ctx.attr.strip_prefix.get(host, "")

    if not url:
        asset_tmpl = _OSSLSIGNCODE_ASSET.get(host)
        if not asset_tmpl:
            fail("no osslsigncode asset mapping for host '{}'".format(host))
        asset = asset_tmpl.format(v = version)
        key = "{}/{}".format(version, asset)
        if key not in OSSLSIGNCODE_VERSIONS:
            fail("no known osslsigncode sha256 for '{}'".format(key))
        sha = _trim_sha256_prefix(OSSLSIGNCODE_VERSIONS[key])
        url = _OSSLSIGNCODE_BASE_URL.format(v = version, a = asset)

        if not strip_prefix:
            strip_prefix = asset
            if strip_prefix.endswith(".tar.gz"):
                strip_prefix = strip_prefix[:-7]
            elif strip_prefix.endswith(".zip"):
                strip_prefix = strip_prefix[:-4]

    ctx.download_and_extract(
        url = url,
        output = ".",
        sha256 = _trim_sha256_prefix(sha),
        strip_prefix = strip_prefix,
    )

    bin_name = "osslsigncode.exe" if windows else "osslsigncode"
    ctx.file("BUILD.bazel", _emit_filegroup_build("osslsigncode", bin_name))

osslsigncode_repo = repository_rule(
    implementation = _osslsigncode_repo_impl,
    doc = "Repository rule that downloads osslsigncode for the host platform.",
    attrs = {
        "version": attr.string(default = "2.14"),
        "urls": attr.string_dict(default = {}),
        "sha256": attr.string_dict(default = {}),
        "strip_prefix": attr.string_dict(default = {}),
    },
)

def _openssl_local_impl(ctx):
    binpath = ctx.path(ctx.attr.path)
    if not binpath.exists:
        fail("openssl path '{}' does not exist".format(ctx.attr.path))

    ctx.symlink(binpath, "openssl")
    ctx.file("BUILD.bazel", _emit_filegroup_build("openssl", "openssl"))

openssl_local_repo = repository_rule(
    implementation = _openssl_local_impl,
    attrs = {
        "path": attr.string(mandatory = True),
    },
)

def _openssl_label_impl(ctx):
    ctx.file("BUILD.bazel", "\n".join([
        'package(default_visibility = ["//visibility:public"])',
        'alias(name = "openssl", actual = "{s}")'.format(s = ctx.attr.label),
        "",
    ]))

openssl_label_repo = repository_rule(
    implementation = _openssl_label_impl,
    attrs = {
        "label": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
)
