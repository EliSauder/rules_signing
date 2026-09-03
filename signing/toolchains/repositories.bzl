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
    "darwin_amd64": "osslsigncode-{v}-macos-amd64.zip",
    "darwin_arm64": "osslsigncode-{v}-macos-arm64.zip",
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

_OS_CONSTRAINT = {
    "linux": "@platforms//os:linux",
    "darwin": "@platforms//os:macos",
    "windows": "@platforms//os:windows",
}

_CPU_CONSTRAINT = {
    "amd64": "@platforms//cpu:x86_64",
    "arm64": "@platforms//cpu:aarch64",
    "arm": "@platforms//cpu:armv7",
}

def _exec_constraints(host):
    os_key, _, arch_key = host.partition("_")
    constraints = []
    if os_key in _OS_CONSTRAINT:
        constraints.append(_OS_CONSTRAINT[os_key])
    if arch_key in _CPU_CONSTRAINT:
        constraints.append(_CPU_CONSTRAINT[arch_key])
    return constraints

def _emit_toolchain_build(name, src, host, rule_name, toolchain_type, data = []):
    """Emits a BUILD file exposing the tool plus a registrable toolchain.

    The toolchain lives in the generated repository rather than in
    //signing/toolchains so that this module never has to reference these
    repositories itself. That keeps the tool repositories opt-in: downstream
    consumers declare and register their own, and nothing is forced on them.

    `data` is only relevant to rules whose implementation accepts a `data`
    attribute (currently just openssl_toolchain, for Windows' sibling DLLs);
    it's omitted from the generated target entirely when empty so it never
    trips over rules that don't define that attribute.
    """
    constraints = _exec_constraints(host)
    data_attr = ""
    if data:
        data_attr = "    data = [{}],\n".format(
            ", ".join(['"{}"'.format(d) for d in data]),
        )
    return "\n".join([
        'load("{}", "{}")'.format(str(Label("@rules_signing//signing/toolchains:toolchains.bzl")), rule_name),
        "",
        'package(default_visibility = ["//visibility:public"])',
        "",
        'filegroup(name = "{n}_file", srcs = ["{s}"])'.format(n = name, s = src),
        "",
        "{r}(".format(r = rule_name),
        '    name = "{n}_toolchain_impl",'.format(n = name),
        '    {n} = ":{n}_file",'.format(n = name),
        data_attr +
        ")",
        "",
        "toolchain(",
        '    name = "{n}_toolchain",'.format(n = name),
        "    exec_compatible_with = [{}],".format(
            ", ".join(['"{}"'.format(c) for c in constraints]),
        ),
        '    toolchain = ":{n}_toolchain_impl",'.format(n = name),
        '    toolchain_type = "{}",'.format(str(Label(toolchain_type))),
        ")",
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
    ctx.file("BUILD.bazel", _emit_toolchain_build(
        name = "cosign",
        src = out,
        host = host,
        rule_name = "cosign_toolchain",
        toolchain_type = "@rules_signing//signing/toolchains:cosign_toolchain_type",
    ))

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
    ctx.file("BUILD.bazel", _emit_toolchain_build(
        name = "osslsigncode",
        src = bin_name,
        host = host,
        rule_name = "osslsigncode_toolchain",
        toolchain_type = "@rules_signing//signing/toolchains:osslsigncode_toolchain_type",
    ))

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

def _openssl_build(src, host, data = []):
    """Emits a BUILD file exposing openssl as a registrable toolchain.

    Unlike cosign and osslsigncode, openssl is not downloaded here. It is
    either adopted from the host or taken from a target another module builds,
    so the caller supplies the label to wrap.
    """
    return _emit_toolchain_build(
        name = "openssl",
        src = src,
        host = host,
        rule_name = "openssl_toolchain",
        toolchain_type = "@rules_signing//signing/toolchains:openssl_toolchain_type",
        data = data,
    )

def _openssl_local_impl(ctx):
    # `path` doubles as either a literal filesystem path (e.g.
    # "/usr/bin/openssl") or a bare program name to resolve against PATH
    # (e.g. "openssl"), so the same tag works unmodified across Linux, macOS
    # and Windows hosts, all of which ship openssl but at different paths.
    binpath = ctx.path(ctx.attr.path)
    if not binpath.exists:
        binpath = ctx.which(ctx.attr.path)
    if not binpath:
        fail("openssl '{}' not found as a path or on PATH".format(ctx.attr.path))
    binpath = binpath.realpath

    host, windows = _host_platform(ctx)

    # Windows resolves an executable by exact filename -- unlike POSIX
    # exec(), CreateProcess() does not fall back to appending ".exe" for a
    # name that lacks it. sign_tool invokes this binary directly (not
    # through a shell that would apply PATHEXT), so the symlink has to carry
    # the same extension the real binary uses or it fails with
    # `FileNotFoundError: [WinError 2]` at signing time.
    out = "openssl.exe" if windows else "openssl"
    ctx.symlink(binpath, out)
    dlls = []

    if windows:
        # Unlike the Linux/macOS build (statically linked, or resolved via
        # rpath/@loader_path), Windows' openssl.exe is a thin stub that
        # dynamically loads libcrypto/libssl DLLs from its own directory.
        # Symlinking only the exe leaves those DLLs unresolved, which fails
        # at signing time with STATUS_DLL_NOT_FOUND (exit code 3221225781)
        # rather than anything mentioning a missing DLL by name. Symlink
        # every DLL next to it so the loader finds them the same way it
        # would beside the original binary.
        bindir = binpath.dirname
        if bindir:
            for entry in bindir.readdir():
                if entry.basename.lower().endswith(".dll"):
                    ctx.symlink(entry, entry.basename)
                    dlls.append(entry.basename)

    ctx.file("BUILD.bazel", _openssl_build(out, host, data = dlls))

openssl_local_repo = repository_rule(
    implementation = _openssl_local_impl,
    doc = "Repository rule that adopts an openssl binary already present on " +
          "the host, either at a literal path or resolved from PATH.",
    attrs = {
        "path": attr.string(mandatory = True),
    },
)

def _openssl_label_impl(ctx):
    # No exec constraints: the referenced target is built by Bazel for
    # whichever exec platform the action runs on, so pinning the host that
    # happened to evaluate this repository rule would be wrong.
    ctx.file("BUILD.bazel", _openssl_build(str(ctx.attr.label), ""))

openssl_label_repo = repository_rule(
    implementation = _openssl_label_impl,
    doc = "Repository rule that wraps an openssl binary built by another module.",
    attrs = {
        "label": attr.label(
            cfg = "exec",
            executable = True,
            mandatory = True,
        ),
    },
)
