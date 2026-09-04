#!/usr/bin/env python3
"""Cross-platform signer orchestration for rules_signing."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
import lief

from typing import Dict, Iterable, Optional, Sequence, Tuple


_OSSLSIGNCODE_EXT = (
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".cat",
    ".ocx",
    ".efi",
    ".appx",
    ".cab",
    ".ps1",
    ".ps1xml",
    ".psc1",
    ".psd1",
    ".psm1",
    ".cdxml",
    ".mof",
    ".js",
)

_CODESIGN_EXT = (".app", ".pkg", ".dmg")
_PLACEHOLDER_RE = re.compile(r"\{([^{}]+)\}")


def sniff_binary_format(path: str) -> str:
    """Identifies Mach-O/PE binaries by content, returning a tool name or "".

    Executables frequently ship without an extension (the norm for Mach-O on
    macOS), so the filename is not a reliable signal. LIEF parses the actual
    headers, which also avoids misreading look-alike magic numbers such as
    Java class files sharing 0xCAFEBABE with universal Mach-O binaries.
    """

    if not os.path.exists(path) or os.path.isdir(path):
        return ""

    # no try except since it is better to fail than to mistakenly sign
    # something incorrectly.
    if lief.is_macho(path):
        return "codesign"
    if lief.is_pe(path):
        return "osslsigncode"
    return ""


def detect_tool(path: str, infile: Optional[str] = None) -> str:
    p = path.lower()
    if p.endswith(_OSSLSIGNCODE_EXT):
        return "osslsigncode"
    if p.endswith(_CODESIGN_EXT):
        return "codesign"
    if infile:
        sniffed = sniff_binary_format(infile)
        if sniffed:
            return sniffed
    return "cosign"


def load_stamp_files(paths: Iterable[str]) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for p in paths:
        if not p:
            continue
        path = pathlib.Path(p)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            key = parts[0]
            value = parts[1] if len(parts) > 1 else ""
            data[key] = value
    return data


def unescape_param_file_line(line: str) -> str:
    """Reverses Bazel's `multiline` parameter-file escaping.

    Bazel writes each argument on its own line after replacing `\\` with
    `\\\\` and a newline with `\\n`, so an argument may legally contain
    either sequence and must be decoded rather than used verbatim.
    """

    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            nxt = line[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


ARGS_FILE_FLAG = "--args-file"


def expand_argfiles(argv: Sequence[str], _depth: int = 0) -> list:
    """Expands `--args-file` arguments into the arguments the file contains.

    Argument files let a caller keep certificate paths, passwords and other
    options out of a command line that would otherwise be visible to other
    processes, embedded into a generated script, or subject to another tool's
    quoting rules. That is what makes it possible to invoke this tool from
    inside a third-party build step (for example NSIS' `!finalize` and
    `!uninstfinalize`) with nothing but a fixed two-token command.

    Two conventions are deliberately *not* used here:

    `fromfile_prefix_chars`, argparse's own support, opens the file with the
    interpreter's locale encoding. On Windows that is the ANSI code page,
    which cannot represent every path or password a caller might legitimately
    pass. Reading the file as UTF-8 here keeps arguments intact on every
    platform, matching how `--rel-src-manifest` is handled.

    The customary `@file` spelling is unsafe for this tool's purpose. The
    Cygwin/MSYS2 runtime, which backs Git for Windows' `bash`, expands
    `@file` arguments itself before the callee ever runs, and it splits the
    file on *whitespace* rather than on lines. Any argument containing a
    space -- a signature description, a certificate subject, a path under
    `Program Files` -- is silently torn into several arguments. Since the
    whole point of an argument file here is to survive being handed through
    an intermediary process, the flag must be one no intermediary claims.

    An argument file may itself use `--args-file`; nesting is bounded to
    catch cycles.
    """

    if _depth > 16:
        raise SystemExit(
            "sign_tool: argument files are nested more than 16 levels deep, "
            "which usually means one of them refers to itself"
        )

    out = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == ARGS_FILE_FLAG:
            if i + 1 >= len(argv):
                raise SystemExit(
                    "sign_tool: {} needs a path".format(ARGS_FILE_FLAG)
                )
            path = argv[i + 1]
            i += 2
        elif arg.startswith(ARGS_FILE_FLAG + "="):
            path = arg[len(ARGS_FILE_FLAG) + 1 :]
            i += 1
        else:
            out.append(arg)
            i += 1
            continue

        try:
            text = pathlib.Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(
                "sign_tool: cannot read argument file {!r}: {}".format(path, exc)
            )
        lines = [unescape_param_file_line(l) for l in text.splitlines()]
        out.extend(expand_argfiles([l for l in lines if l], _depth + 1))
    return out


def replace_path(src: str, dst: str) -> None:
    """Moves `src` onto `dst`, replacing whatever is already there.

    Used for in-place signing, where the signer cannot write to its own input
    and the result therefore has to be produced beside it and moved over.
    """

    dst_path = pathlib.Path(dst)
    if dst_path.is_dir() and not dst_path.is_symlink():
        shutil.rmtree(dst_path)
    elif dst_path.exists() or dst_path.is_symlink():
        dst_path.unlink()
    ensure_parent(dst)
    shutil.move(src, dst)


def load_rel_src_manifest(path: str) -> list:
    """Reads (relpath, src) pairs written by sign.bzl's `rel_src_manifest`.

    The pairs travel through a file instead of repeated --rel/--src argv
    tokens so that file names are never subject to the OS's native
    command-line encoding (notably Windows' ANSI code page, which cannot
    represent every Unicode character); reading the manifest as UTF-8 text
    keeps names intact on every platform.
    """

    pairs = []
    if not path:
        return pairs
    for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        relpath, _, src = line.partition("\t")
        pairs.append((relpath, src))
    return pairs


def parse_defaults(kvs: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for kv in kvs:
        if not kv:
            continue
        if "=" in kv:
            key, value = kv.split("=", 1)
        else:
            key, value = kv, ""
        if key:
            out[key] = value
    return out


def interpolate_template(
    template: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
) -> Tuple[str, bool]:
    unresolved = False

    def replace(match: re.Match[str]) -> str:
        nonlocal unresolved
        key = match.group(1)
        if key in stamps:
            return stamps[key]
        if key in defaults:
            return defaults[key]
        unresolved = True
        return ""

    return _PLACEHOLDER_RE.sub(replace, template), unresolved


def resolve_template(
    template: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
) -> Optional[str]:
    value, unresolved = interpolate_template(template, stamps, defaults)
    if unresolved:
        return None
    return value


def ensure_parent(path: str) -> None:
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)


def is_pem_certificate(path: str) -> bool:
    """Reports whether a certificate file holds PEM rather than PKCS#12 data.

    Signing material reaches this tool from several places (a checked-in file,
    a `{KEY}`-stamped path, or a base64 blob decoded into a scratch file), and
    only some of them carry a meaningful extension. Sniffing the PEM armour
    keeps the format decision correct for all of them, which matters because
    PEM and PKCS#12 need entirely different flags from the underlying signers.
    """

    try:
        with open(path, "rb") as handle:
            head = handle.read(64)
    except OSError:
        return False
    return b"-----BEGIN" in head


def is_cosign_private_key(path: str) -> bool:
    """Reports whether a file is already a cosign-format signing key.

    cosign wraps keys in its own encrypted envelope rather than reading a
    standard PEM key, so a key it produced has to be told apart from the
    ordinary certificate material every other signer consumes.
    """

    try:
        with open(path, "rb") as handle:
            head = handle.read(128)
    except OSError:
        return False
    return b"SIGSTORE PRIVATE KEY" in head


def pkcs12_to_pem(cert_path: str, password: str, tmpdir: str, openssl: str = "") -> str:
    """Converts PKCS#12 signing material to the unified PEM cosign requires.

    cosign only reads PEM, so a PKCS#12 certificate that works with the other
    two signers would otherwise be unusable here. openssl is an optional
    toolchain rather than a hard dependency, because most builds never need
    this conversion; when it is absent the caller is told exactly how to
    proceed instead of failing with a cryptic error from cosign.
    """

    if not openssl:
        raise ValueError(
            "sign_tool: cosign requires PEM signing material but the "
            "certificate is PKCS#12 ({}). Either supply a PEM certificate "
            "(private key and certificate in one file) via certificate_file, "
            "or register the optional openssl toolchain so it can be "
            "converted during the build. See the 'Signing with a single "
            "certificate' section of the rules_signing README."
            .format(cert_path)
        )

    out = pathlib.Path(tmpdir) / "cert-from-p12.pem"
    env = dict(os.environ)
    env["RULES_SIGNING_P12_PASSWORD"] = password
    cmd = [
        openssl,
        "pkcs12",
        "-in",
        cert_path,
        "-nodes",
        # Only the private key is extracted. cosign's trust model is a bare
        # public key rather than an X.509 chain, so it ignores certificates --
        # and it reads the first PEM block in the file, which would be a
        # certificate rather than the key if they were included.
        "-nocerts",
        "-passin",
        "env:RULES_SIGNING_P12_PASSWORD",
        "-out",
        str(out),
    ]
    try:
        run_cmd(cmd, env=env)
    except subprocess.CalledProcessError:
        # Certificates written by older tools use ciphers that OpenSSL 3 only
        # exposes through its legacy provider.
        run_cmd(cmd + ["-legacy"], env=env)
    return str(out)


def resolve_cosign_key(
    *, tool: str, cert_path: str, password: str, tmpdir: str, openssl: str = ""
) -> str:
    """Returns a cosign-usable signing key for arbitrary certificate material.

    cosign is the odd one out: osslsigncode and rcodesign both consume ordinary
    certificate/key files, while cosign insists on its own key envelope. Left
    alone that would force a separate credential just for cosign, so any
    ordinary key is imported into cosign's format here. `import-key-pair` only
    rewraps the key it is given, so the imported key is the same key, which is
    what lets one certificate back all three signers.
    """

    if is_cosign_private_key(cert_path):
        return cert_path

    if not is_pem_certificate(cert_path):
        cert_path = pkcs12_to_pem(cert_path, password, tmpdir, openssl)

    prefix = pathlib.Path(tmpdir) / "cosign-imported"
    imported = prefix.with_suffix(".key")
    if not imported.is_file():
        run_cmd(
            [
                tool,
                "import-key-pair",
                "--key",
                cert_path,
                "--output-key-prefix",
                str(prefix),
                "--yes",
            ],
            env=cosign_env(password),
        )
    return str(imported)


def cosign_env(password: str) -> Dict[str, str]:
    """Builds the environment cosign uses to unlock (or protect) a key."""

    env = dict(os.environ)
    env["COSIGN_PASSWORD"] = password
    return env


def passthrough(src: str, out: str) -> None:
    """Copies contents of source to out with no modifications"""
    if pathlib.Path(src).is_dir():
        out_path = pathlib.Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            shutil.rmtree(out_path)

        # Symlinks are resolved rather than recreated. Bazel stages the
        # contents of a directory input as symlinks into the execroot, so
        # preserving them would leave the output tree pointing at paths that do
        # not outlive the action.
        shutil.copytree(src, out, symlinks=False)
        for root, dirs, files in os.walk(out):
            for dname in dirs:
                dpath = pathlib.Path(root) / dname
                dpath.chmod(dpath.stat().st_mode | stat.S_IWUSR)
            for fname in files:
                fpath = pathlib.Path(root) / fname
                if not fpath.is_symlink():
                    fpath.chmod(fpath.stat().st_mode | stat.S_IWUSR)
        out_path.chmod(out_path.stat().st_mode | stat.S_IWUSR)
        return
    ensure_parent(out)
    shutil.copy2(src, out)
    out_path = pathlib.Path(out)
    if not out_path.is_symlink():
        out_path.chmod(out_path.stat().st_mode | stat.S_IWUSR)


def render_cert_material(
    *,
    cert_template: str,
    cert_encoding: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
) -> Tuple[Optional[bytes], bool]:
    """Renders a `certificate` template into raw certificate bytes.

    Used by the `certificate` rule's `resolve-cert` action (see
    `resolve_cert_mode`) to turn a `{KEY}`-templated `certificate` attribute
    into real bytes exactly once, rather than in every `sign` action that
    shares the certificate.

    Returns a `(data, unresolved)` pair:
      - `unresolved=True` means a `{KEY}` placeholder could not be resolved
        from `stamps` or `defaults` at all -- always a hard error, since it
        usually indicates a workspace status key that was never wired up.
      - `data=None` (with `unresolved=False`) means a `path`-encoded template
        rendered to a location that does not exist on disk. This is
        deliberately tolerated rather than treated as an error, so a
        `certificate` target whose real secret is unavailable in this build
        environment (e.g. a contributor's machine without production
        credentials) does not hard-fail the build; downstream `sign` actions
        treat a missing/empty certificate the same as none configured.
    """
    rendered, unresolved = interpolate_template(cert_template, stamps, defaults)
    if unresolved:
        return None, True

    if cert_encoding == "base64":
        return base64.b64decode(rendered.encode("utf-8")), False

    src = pathlib.Path(rendered)
    if not src.is_file():
        return None, False
    return src.read_bytes(), False


def resolve_cert_path(*, cert_file: str) -> Optional[str]:
    """Returns `cert_file` if it holds resolved certificate data.

    The `certificate` rule resolves any `certificate` template into a File
    ahead of time (see `certificate.bzl` and `resolve_cert_mode`), so by the
    time a `sign` action runs, `cert_file` is always either empty or already
    the certificate's final bytes -- there is no template left to interpolate
    here. An empty file is the sentinel the resolver writes when it could not
    resolve real material (see `render_cert_material`); it is treated the
    same as no certificate at all.
    """
    if not cert_file:
        return None
    path = pathlib.Path(cert_file)
    if not path.is_file() or path.stat().st_size == 0:
        return None
    return cert_file


def resolve_password(
    *,
    password_template: str,
    password_env: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
) -> str:
    if password_template:
        rendered = resolve_template(password_template, stamps, defaults)
        return rendered or ""
    if password_env:
        return os.environ.get(password_env, "")
    return ""


def resolve_identity(
    *,
    identity_template: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
) -> str:
    if not identity_template:
        return ""
    rendered = resolve_template(identity_template, stamps, defaults)
    return rendered or ""


def run_cmd(cmd: Sequence[str], *, env: Optional[Dict[str, str]] = None) -> None:
    subprocess.run(cmd, check=True, env=env)

def run_cmd_capture(cmd: Sequence[str], *, env: Optional[Dict[str, str]] = None) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)
    return result.stdout

_PUBLIC_REKOR_URL = "https://rekor.sigstore.dev"

# What `timestamp_url = "default"` resolves to. rcodesign documents Apple's
# server as its own default; osslsigncode has no built-in default, so the
# most widely used public Authenticode timestamp authority stands in for one.
_DEFAULT_TIMESTAMP_URLS = {
    "codesign": "http://timestamp.apple.com/ts01",
    "osslsigncode": "http://timestamp.digicert.com",
}


def resolve_timestamp_url(timestamp_url: str, signer: str) -> str:
    """Maps the `timestamp_url` setting onto a timestamp authority URL.

    Empty means no timestamping, which is the default: countersigning contacts
    a third party and tells it when you build, so it is opt-in like any other
    network access. `default` selects the well-known authority for the signer
    in use, and any other value is a specific server's URL.

    Returning empty is not the same as leaving the tool to its own devices:
    rcodesign timestamps against Apple's server unless actively told not to,
    so callers must translate this into whatever disables that.
    """

    if not timestamp_url:
        return ""
    if timestamp_url == "default":
        return _DEFAULT_TIMESTAMP_URLS[signer]
    if not timestamp_url.startswith(("https://", "http://")):
        raise ValueError(
            "sign_tool: timestamp_url must be empty (do not timestamp), "
            "'default' (the well-known authority for the signer in use), or "
            "the URL of a timestamp server; got '{}'".format(timestamp_url)
        )
    return timestamp_url


def resolve_rekor_url(transparency_log: str) -> str:
    """Maps the `transparency_log` setting onto a Rekor instance URL.

    Empty means no transparency log, which is the default: publishing a hash of
    the build output to a public ledger, and making every signing action a
    network call to do it, is not something a build rule should do unasked.
    `default` opts in to the public Sigstore instance, and any other value is
    the URL of a specific instance, which is how a private Rekor deployment is
    selected.
    """

    if not transparency_log:
        return ""
    if transparency_log == "default":
        return _PUBLIC_REKOR_URL
    if not transparency_log.startswith(("https://", "http://")):
        raise ValueError(
            "sign_tool: transparency_log must be empty (do not publish), "
            "'default' (the public Sigstore instance at {}), or the URL of a "
            "Rekor instance; got '{}'".format(_PUBLIC_REKOR_URL, transparency_log)
        )
    return transparency_log


def cosign_signing_config(tool: str, tmpdir: str, transparency_log: str = "") -> str:
    """Builds the Sigstore signing config that decides where signatures go.

    cosign contacts the public Rekor log unless it is handed a signing config
    saying otherwise, so one is always supplied. With no transparency log the
    config declares no online services at all, keeping signing local; otherwise
    it names the one Rekor instance to publish to. Either way the config is
    produced by cosign itself, so its schema always matches the version of the
    tool in use.
    """

    url = resolve_rekor_url(transparency_log)

    # Distinct settings must not share a cached config, and the URL is not
    # safe to put in a filename.
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12] if url else "offline"
    config_path = pathlib.Path(tmpdir) / "cosign-signing-config-{}.json".format(key)
    if config_path.is_file():
        return str(config_path)

    cmd = [tool, "signing-config", "create", "--out", str(config_path)]
    if url:
        # start-time is the epoch because these services are not being rotated
        # on a schedule; the entry simply has to be valid whenever we sign.
        cmd.extend([
            "--rekor",
            "url={},api-version=1,start-time=1970-01-01T00:00:00Z,operator={}".format(
                url, urllib.parse.urlparse(url).hostname or url
            ),
            "--rekor-config",
            "ANY",
        ])
    run_cmd(cmd)
    return str(config_path)


def cosign_sign_blob_cmd(
    *,
    tool: str,
    cert_path: str,
    bundle_path: str,
    infile: str,
    tmpdir: str,
    transparency_log: str = "",
) -> list:
    return [
        tool,
        "sign-blob",
        "--yes",
        "--key",
        cert_path,
        "--bundle",
        bundle_path,
        "--signing-config",
        cosign_signing_config(tool, tmpdir, transparency_log),
        infile,
    ]


def sign_blob_with_cosign(
    *,
    tool: str,
    infile: str,
    outfile: str,
    cert_path: Optional[str],
    password: str,
    tmpdir: str = "",
    openssl: str = "",
    transparency_log: str = "",
) -> None:
    passthrough(infile, outfile)
    if not cert_path:
        return
    if not tool:
        raise ValueError("sign_tool: cosign tool path is required for detached signatures")

    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = password if password else ""
    cert_path = resolve_cosign_key(
        tool=tool,
        cert_path=cert_path,
        password=password,
        tmpdir=tmpdir,
        openssl=openssl,
    )
    bundle_path = outfile + ".bundle.json"
    signature = run_cmd_capture(
        cosign_sign_blob_cmd(
            tool=tool,
            cert_path=cert_path,
            bundle_path=bundle_path,
            infile=infile,
            tmpdir=tmpdir,
            transparency_log=transparency_log,
        ),
        env=env,
    ).strip()
    if not signature:
        # cosign v3 writes the signature only into the Sigstore bundle and
        # emits nothing on stdout, so recover it from the bundle instead.
        signature = read_signature_from_bundle(bundle_path)
    if not signature:
        raise ValueError(
            "sign_tool: cosign produced no detached signature for '{}'".format(infile)
        )
    pathlib.Path(outfile + ".sig").write_text(signature + "\n", encoding="utf-8")


def read_signature_from_bundle(bundle_path: str) -> str:
    """For OCI layout images
    cosign v3 writes the signature only into the Sigstore bundle and
    emits nothing on stdout, so get it from the bundle instead.
    """

    path = pathlib.Path(bundle_path)
    if not path.is_file():
        return ""
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ""
    signature = bundle.get("messageSignature", {}).get("signature", "")
    if signature:
        return signature
    return bundle.get("base64Signature", "")


def is_oci_layout(path: str) -> bool:
    p = pathlib.Path(path)
    return (p / "oci-layout").is_file() and (p / "index.json").is_file() and (p / "blobs").is_dir()


def resolve_root_blob_for_index(layout_dir: str) -> pathlib.Path:
    """Resolves the root blob of the oci layout using the manifest digest."""
    index_path = pathlib.Path(layout_dir) / "index.json"
    index_data = json.loads(index_path.read_text(encoding="utf-8"))
    manifests = index_data.get("manifests")
    if not manifests:
        raise ValueError("sign_tool: OCI layout index.json has no manifests")
    digest = manifests[0].get("digest", "")
    parts = digest.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("sign_tool: unsupported OCI digest '{}'".format(digest))
    blob = pathlib.Path(layout_dir) / "blobs" / parts[0] / parts[1]
    if not blob.is_file():
        raise ValueError("sign_tool: OCI blob for digest '{}' was not found".format(digest))
    return blob


def sign_oci_layout_with_cosign(
    *,
    tool: str,
    infile: str,
    outfile: str,
    cert_path: Optional[str],
    password: str,
    tmpdir: str = "",
    openssl: str = "",
    transparency_log: str = "",
) -> None:
    passthrough(infile, outfile)

    if not is_oci_layout(outfile) or not cert_path:
        return
    if not tool:
        raise ValueError("sign_tool: cosign tool path is required to sign OCI image layouts")

    root_blob = resolve_root_blob_for_index(outfile)
    signature_dir = pathlib.Path(outfile) / "signatures"
    signature_dir.mkdir(parents=True, exist_ok=True)
    bundle = signature_dir / "{}.bundle.json".format(root_blob.name)

    env = os.environ.copy()
    env["COSIGN_PASSWORD"] = password if password else ""
    cert_path = resolve_cosign_key(
        tool=tool,
        cert_path=cert_path,
        password=password,
        tmpdir=tmpdir,
        openssl=openssl,
    )

    run_cmd(
        cosign_sign_blob_cmd(
            tool=tool,
            cert_path=cert_path,
            bundle_path=str(bundle),
            infile=str(root_blob),
            tmpdir=tmpdir,
            transparency_log=transparency_log,
        ),
        env=env,
    )


def sign_with_osslsigncode(
    *,
    tool: str,
    infile: str,
    outfile: str,
    timestamp_url: str,
    name: str,
    url: str,
    cert_path: Optional[str],
    password: str,
    ca_path: str = "",
) -> None:
    if not cert_path:
        passthrough(infile, outfile)
        return

    ensure_parent(outfile)
    if is_pem_certificate(cert_path):
        # A unified PEM (certificate plus unencrypted private key in one file)
        # is handed to osslsigncode directly; it has no PKCS#12 container to
        # unwrap and therefore takes no password.
        cmd = [tool, "sign", "-certs", cert_path, "-key", cert_path, "-h", "sha256"]
    else:
        cmd = [tool, "sign", "-pkcs12", cert_path, "-h", "sha256"]
        if password:
            cmd.extend(["-pass", password])
    if ca_path:
        # Embeds the issuing chain in the signature so a verifier can build a
        # path to the root without having to source the intermediates itself.
        cmd.extend(["-ac", ca_path])
    timestamp_url = resolve_timestamp_url(timestamp_url, "osslsigncode")
    if timestamp_url:
        cmd.extend(["-t", timestamp_url])
    if name:
        cmd.extend(["-n", name])
    if url:
        cmd.extend(["-i", url])
    cmd.extend(["-in", infile, "-out", outfile])
    run_cmd(cmd)


def sign_with_codesign(
    *,
    tool: str,
    infile: str,
    outfile: str,
    timestamp_url: str,
    options: str,
    entitlements: str,
    cert_path: Optional[str],
    password: str,
    identity: str,
    ca_path: str = "",
) -> None:
    """Sign a Mach-O binary, bundle, DMG or PKG with rcodesign.

    The codesign.bzl toolchain ships `rcodesign` (apple-codesign) rather than
    Apple's /usr/bin/codesign, so signing works on Linux and Windows workers
    too and needs no keychain. rcodesign takes explicit input/output paths and
    recursively signs bundle directories itself.
    """
    if not tool:
        raise ValueError(
            "sign_tool: codesign tool path is required; register the codesign "
            "toolchain (@codesign.bzl//toolchain:all)"
        )

    if not cert_path:
        # Matches the other signers: with no signing material available the
        # artifact is passed through unchanged rather than ad-hoc signed.
        passthrough(infile, outfile)
        return

    ensure_parent(outfile)
    cmd = [tool, "sign"]

    if is_pem_certificate(cert_path):
        # A unified PEM (certificate plus unencrypted private key in one file)
        # is read directly and, having no PKCS#12 container, takes no password.
        cmd.extend(["--pem-file", cert_path])
    else:
        cmd.extend(["--p12-file", cert_path])
        # rcodesign requires the flag even for an empty password.
        cmd.extend(["--p12-password", password or ""])
    if ca_path:
        # rcodesign pairs the signing key with the first certificate it sees
        # and treats every later one as part of the issuing chain, so the CA
        # file is supplied as an additional PEM source.
        cmd.extend(["--pem-file", ca_path])
    # Unlike every other setting here, omitting this one is not neutral:
    # rcodesign countersigns against Apple's timestamp server by default, so
    # the flag is always passed and `none` is what turns that default off.
    cmd.extend([
        "--timestamp-url",
        resolve_timestamp_url(timestamp_url, "codesign") or "none",
    ])
    if entitlements:
        cmd.extend(["--entitlements-xml-file", entitlements])
    if identity:
        cmd.extend(["--binary-identifier", identity])
    for flag in [o.strip() for o in options.split(",") if o.strip()]:
        cmd.extend(["--code-signature-flags", flag])

    cmd.extend([infile, outfile])
    run_cmd(cmd)


def sign_file(
    *,
    selected: str,
    infile: str,
    outfile: str,
    args: argparse.Namespace,
    cert_path: Optional[str],
    password: str,
    identity: str,
    tmpdir: str = "",
) -> None:
    if selected == "osslsigncode":
        sign_with_osslsigncode(
            tool=args.osslsigncode_tool,
            infile=infile,
            outfile=outfile,
            timestamp_url=args.timestamp_url,
            name=args.name,
            url=args.url,
            ca_path=args.ca_file,
            cert_path=cert_path,
            password=password,
        )
    elif selected == "codesign":
        sign_with_codesign(
            tool=args.codesign_tool,
            infile=infile,
            outfile=outfile,
            timestamp_url=args.timestamp_url,
            options=args.options,
            entitlements=args.entitlements,
            ca_path=args.ca_file,
            cert_path=cert_path,
            password=password,
            identity=identity,
        )
    elif selected == "cosign":
        sign_blob_with_cosign(
            tool=args.cosign_tool,
            infile=infile,
            outfile=outfile,
            tmpdir=tmpdir,
            openssl=args.openssl_tool,
            transparency_log=args.transparency_log,
            cert_path=cert_path,
            password=password,
        )
    else:
        passthrough(infile, outfile)

def sign_directory(
    *,
    tool_mode: str,
    relpath: str,
    selected: str,
    indir: str,
    outdir: str,
    args: argparse.Namespace,
    cert_path: Optional[str],
    password: str,
    identity: str,
    tmpdir: str = "",
) -> None:
    """Signs a directory as the signing target.
    Calling this function implies that the directory itself can be signed using
    some mechanism (e.g. oci layout or apple app/pkg).
    """

    if is_oci_layout(indir) and (selected == "cosign" or selected == "auto"):
        sign_oci_layout_with_cosign(
            tool=args.cosign_tool,
            infile=indir,
            outfile=outdir,
            tmpdir=tmpdir,
            openssl=args.openssl_tool,
            transparency_log=args.transparency_log,
            cert_path=cert_path,
            password=password,
        )
        return

    if selected == "codesign":
        # macOS bundles (.app/.pkg) are directories, but codesign signs
        # them as a single unit rather than file by file.
        staged_input = tempfile.mkdtemp(prefix="codesign-input-", dir=tmpdir or None)
        passthrough(indir, staged_input)
        out_path = pathlib.Path(outdir)
        if out_path.exists():
            shutil.rmtree(out_path)
        sign_with_codesign(
            tool=args.codesign_tool,
            infile=staged_input,
            outfile=outdir,
            timestamp_url=args.timestamp_url,
            options=args.options,
            entitlements=args.entitlements,
            ca_path=args.ca_file,
            cert_path=cert_path,
            password=password,
            identity=identity,
        )
        return

    passthrough(indir, outdir)

    for source_file in pathlib.Path(indir).rglob("*"):
        # is_file() follows symlinks on purpose. Bazel stages the contents of a
        # directory input as symlinks into the execroot, so skipping symlinks
        # here would silently leave every file in the directory unsigned.
        if not source_file.is_file():
            continue
        relative_path = source_file.relative_to(indir).as_posix()
        sign_one(
            tool_mode=tool_mode,
            relpath=relative_path,
            infile=str(source_file),
            outfile=str(pathlib.Path(outdir) / relative_path),
            args=args,
            tmpdir=tmpdir,
            cert_path=cert_path,
            password=password,
            identity=identity,
        )

def sign_one(
    *,
    tool_mode: str,
    relpath: str,
    infile: str,
    outfile: str,
    args: argparse.Namespace,
    cert_path: Optional[str],
    password: str,
    identity: str,
    tmpdir: str = "",
) -> None:
    selected = tool_mode
    if selected == "auto":
        # Pass the real path so extensionless Mach-O/PE binaries are detected
        # from their header rather than falling through to a detached signature.
        selected = detect_tool(relpath, infile)
    if not selected:
        selected = "cosign"

    if pathlib.Path(infile).is_dir():
        sign_directory(
            selected=selected,
            tool_mode=tool_mode,
            relpath=relpath,
            args=args,
            outdir=outfile,
            indir=infile,
            identity=identity,
            tmpdir=tmpdir,
            cert_path=cert_path,
            password=password,
        )
        return

    sign_file(
        selected=selected,
        infile=infile,
        outfile=outfile,
        args=args,
        tmpdir=tmpdir,
        cert_path=cert_path,
        password=password,
        identity=identity,
    )

def resolve_cert_mode(args: argparse.Namespace) -> None:
    """Handles `--mode resolve-cert`.

    Renders a `certificate` template (a base64 blob or an on-disk path,
    either possibly holding `{KEY}` stamp placeholders) into a single output
    file. The `certificate` rule runs this once per certificate, evaluating
    its own `stamp` attribute, so `sign` actions consume already-resolved
    certificate material instead of re-interpolating the same template on
    every signing action that shares the certificate.
    """

    stamps = load_stamp_files([args.info_file, args.version_file])
    defaults = parse_defaults(args.stamp_default)

    data, unresolved = render_cert_material(
        cert_template=args.cert_template,
        cert_encoding=args.cert_encoding,
        stamps=stamps,
        defaults=defaults,
    )
    if unresolved:
        raise SystemExit(
            "sign_tool: certificate template {!r} has a {{KEY}} placeholder "
            "that isn't resolved by workspace status or `stamp_defaults`. "
            "Enable stamping for this `certificate` target (`stamp = 1`, or "
            "build with --stamp) or add the key to `stamp_defaults`.".format(
                args.cert_template
            )
        )

    ensure_parent(args.out)
    # An empty file is the sentinel for "no certificate material resolved"
    # (see `render_cert_material`); `sign` treats it exactly like no
    # certificate configured at all instead of failing the build.
    pathlib.Path(args.out).write_bytes(data or b"")


_DN_FIELDS = (
    ("country", "C"),
    ("state", "ST"),
    ("locality", "L"),
    ("organization", "O"),
    ("organizational_unit", "OU"),
    ("common_name", "CN"),
    ("email", "emailAddress"),
)


def escape_openssl_config_value(value: str) -> str:
    """Escapes a value for inclusion in an OpenSSL configuration file.

    Subject fields come straight from a BUILD file, so they can legitimately
    contain characters the config parser treats specially. `#` starts a
    comment and would silently truncate the value, `$` introduces variable
    expansion, and `"`/`\\` drive quoting, all of which would otherwise
    rewrite the subject rather than fail. Newlines cannot be escaped at all --
    they would end the entry -- so they are rejected.
    """

    if "\n" in value or "\r" in value:
        raise SystemExit(
            "sign_tool: certificate subject values cannot contain newlines: "
            "{!r}".format(value)
        )
    return (
        value.replace("\\", "\\\\")
        .replace("$", "\\$")
        .replace('"', '\\"')
        .replace("#", "\\#")
    )


def build_openssl_config(
    *,
    subject: Dict[str, str],
    key_usage: Sequence[str],
    extended_key_usage: Sequence[str],
    subject_alt_names: Sequence[str],
) -> str:
    """Builds the `openssl req` config describing the certificate to issue.

    A config file is used rather than `-subj`/`-addext` because subject values
    are arbitrary user strings: `-subj` gives `/` and `=` a structural meaning
    that a value such as an organization name containing a slash would break,
    while config entries are plain `key = value` lines.
    """

    dn_lines = []
    for attr_name, oid in _DN_FIELDS:
        value = subject.get(attr_name, "")
        if value:
            dn_lines.append("{} = {}".format(oid, escape_openssl_config_value(value)))

    ext_lines = [
        "basicConstraints = critical,CA:FALSE",
        "subjectKeyIdentifier = hash",
    ]
    if key_usage:
        ext_lines.append("keyUsage = critical,{}".format(",".join(key_usage)))
    if extended_key_usage:
        ext_lines.append("extendedKeyUsage = {}".format(",".join(extended_key_usage)))
    if subject_alt_names:
        ext_lines.append("subjectAltName = {}".format(
            ",".join(escape_openssl_config_value(s) for s in subject_alt_names),
        ))

    return "\n".join(
        [
            "[ req ]",
            "distinguished_name = rules_signing_dn",
            "prompt = no",
            "x509_extensions = rules_signing_ext",
            "",
            "[ rules_signing_dn ]",
        ]
        + dn_lines
        + [
            "",
            "[ rules_signing_ext ]",
        ]
        + ext_lines
        + [""],
    )


def generate_private_key(
    *,
    openssl: str,
    key_type: str,
    key_size: int,
    ec_curve: str,
    out: str,
) -> None:
    cmd = [openssl, "genpkey", "-outform", "PEM", "-out", out]
    if key_type == "rsa":
        cmd.extend(["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:{}".format(key_size)])
    elif key_type == "ec":
        cmd.extend([
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:{}".format(ec_curve),
            # Named-curve encoding is what every signer (and Apple's tooling in
            # particular) expects; the explicit-parameters form openssl would
            # otherwise emit is widely rejected.
            "-pkeyopt",
            "ec_param_enc:named_curve",
        ])
    else:
        raise SystemExit(
            "sign_tool: unknown key type {!r}; expected 'rsa' or 'ec'".format(key_type)
        )
    run_cmd(cmd)


def gen_self_signed_mode(args: argparse.Namespace) -> None:
    """Handles `--mode gen-self-signed`.

    Issues a throwaway key pair and a self-signed X.509 certificate for it,
    writing the signing material in the same shapes the `certificate` rule
    accepts: a unified PEM (private key followed by the certificate, which is
    what osslsigncode, rcodesign and cosign all consume) or a PKCS#12 bundle.
    The bare certificate is always written alongside it so verification has a
    trust anchor to point at.

    openssl does the work rather than a Python crypto library because the
    signer already depends on an optional openssl toolchain for PKCS#12
    conversion, and adding an X.509 implementation as a hard runtime
    dependency of every build that merely signs a file would be a much larger
    cost than reusing a tool that is already there.
    """

    if not args.openssl_tool:
        raise SystemExit(
            "sign_tool: generating a self-signed certificate requires the "
            "openssl toolchain. Register it with:\n"
            "    signing_tools.openssl(path = \"openssl\")\n"
            "    register_toolchains(\"@signing_openssl//:openssl_toolchain\")"
        )
    if args.validity_days < 1:
        raise SystemExit("sign_tool: --validity-days must be at least 1")

    stamps = load_stamp_files([args.info_file, args.version_file])
    defaults = parse_defaults(args.stamp_default)
    password = resolve_password(
        password_template=args.password_template,
        password_env=args.password_env,
        stamps=stamps,
        defaults=defaults,
    )

    subject = {
        "common_name": resolve_template(args.common_name, stamps, defaults) or "",
        "country": args.country,
        "state": args.state,
        "locality": args.locality,
        "organization": resolve_template(args.organization, stamps, defaults) or "",
        "organizational_unit": args.organizational_unit,
        "email": args.email,
    }
    if not subject["common_name"]:
        raise SystemExit("sign_tool: --common-name is required and must not be empty")

    config = build_openssl_config(
        subject=subject,
        key_usage=args.key_usage,
        extended_key_usage=args.extended_key_usage,
        subject_alt_names=args.subject_alt_name,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        config_path = tmp / "openssl.cnf"
        config_path.write_text(config, encoding="utf-8")
        key_path = tmp / "key.pem"
        cert_path = tmp / "cert.pem"

        generate_private_key(
            openssl=args.openssl_tool,
            key_type=args.key_type,
            key_size=args.key_size,
            ec_curve=args.ec_curve,
            out=str(key_path),
        )
        run_cmd([
            args.openssl_tool,
            "req",
            "-new",
            "-x509",
            "-{}".format(args.digest),
            "-key",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            str(args.validity_days),
            "-config",
            str(config_path),
            "-extensions",
            "rules_signing_ext",
            "-utf8",
        ])

        ensure_parent(args.out)
        if args.format == "p12":
            env = dict(os.environ)
            env["RULES_SIGNING_P12_PASSWORD"] = password
            run_cmd(
                [
                    args.openssl_tool,
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(key_path),
                    "-in",
                    str(cert_path),
                    "-name",
                    subject["common_name"],
                    "-passout",
                    "env:RULES_SIGNING_P12_PASSWORD",
                    "-out",
                    args.out,
                ],
                env=env,
            )
        else:
            # Key first, then the certificate: osslsigncode is handed the same
            # file as both `-certs` and `-key`, and reads the first matching
            # block of each kind, so a single file has to carry both.
            pathlib.Path(args.out).write_bytes(
                key_path.read_bytes() + cert_path.read_bytes()
            )

        if args.cert_out:
            ensure_parent(args.cert_out)
            pathlib.Path(args.cert_out).write_bytes(cert_path.read_bytes())
        if args.public_key_out:
            ensure_parent(args.public_key_out)
            run_cmd([
                args.openssl_tool,
                "x509",
                "-in",
                str(cert_path),
                "-pubkey",
                "-noout",
                "-out",
                args.public_key_out,
            ])


def sign_mode(args: argparse.Namespace) -> None:
    """Handles `--mode sign`.

    Two input styles are supported:

    * `--rel-src-manifest` with `--out-dir` signs many files at once,
      reproducing each source's relative path under the output directory.
    * `--in`, optionally with `--out`, signs a single file or directory. When
      `--out` is omitted or names the input, the input is signed in place,
      which is what build steps that hand a signer a path to an artifact they
      have already produced (rather than an input/output pair) require.
    """

    if not args.infile and not args.rel_src_manifest:
        raise SystemExit(
            "sign_tool: --mode sign needs either --in (single target) or "
            "--rel-src-manifest with --out-dir (batch)"
        )
    if args.infile and args.rel_src_manifest:
        raise SystemExit(
            "sign_tool: --in and --rel-src-manifest are alternative ways to "
            "name what to sign; pass exactly one"
        )
    if args.rel_src_manifest and not args.out_dir:
        raise SystemExit("sign_tool: --rel-src-manifest requires --out-dir")

    stamps = load_stamp_files([args.info_file, args.version_file])
    defaults = parse_defaults(args.stamp_default)

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = resolve_cert_path(cert_file=args.cert_file)
        password = resolve_password(
            password_template=args.password_template,
            password_env=args.password_env,
            stamps=stamps,
            defaults=defaults,
        )
        identity = resolve_identity(
            identity_template=args.identity_template,
            stamps=stamps,
            defaults=defaults,
        )

        if args.infile:
            infile = os.path.normpath(args.infile)
            if not pathlib.Path(infile).exists():
                raise SystemExit(
                    "sign_tool: --in {!r} does not exist".format(infile)
                )
            outfile = args.out or infile
            in_place = os.path.realpath(outfile) == os.path.realpath(infile)

            # No signer supports reading and writing the same path, so an
            # in-place request is served by signing to scratch space and
            # moving the result over the original afterwards.
            target = outfile
            if in_place:
                staging = pathlib.Path(tmpdir) / "in-place"
                staging.mkdir(parents=True, exist_ok=True)
                target = str(staging / pathlib.Path(infile).name)

            sign_one(
                tool_mode=args.tool,
                relpath=infile,
                infile=infile,
                outfile=target,
                args=args,
                tmpdir=tmpdir,
                cert_path=cert_path,
                password=password,
                identity=identity,
            )

            if in_place:
                replace_path(target, outfile)
            return

        rel_src_pairs = load_rel_src_manifest(args.rel_src_manifest)
        pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        for relpath, src in rel_src_pairs:
            out = str(pathlib.Path(args.out_dir) / relpath)
            sign_one(
                tool_mode=args.tool,
                relpath=relpath,
                infile=src,
                outfile=out,
                args=args,
                tmpdir=tmpdir,
                cert_path=cert_path,
                password=password,
                identity=identity,
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("sign", "resolve-cert", "gen-self-signed"),
        default="sign",
    )
    # Expanded by expand_argfiles before argparse runs; declared here so it
    # shows up in --help.
    parser.add_argument(
        ARGS_FILE_FLAG,
        dest="args_file",
        default="",
        help="read additional arguments, one per line, from this UTF-8 file",
    )
    parser.add_argument("--tool", choices=("auto", "osslsigncode", "codesign", "cosign"), default="auto")
    parser.add_argument("--in", dest="infile", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--rel-src-manifest", default="")

    parser.add_argument("--osslsigncode-tool", default="osslsigncode")
    parser.add_argument("--cosign-tool", default="")
    parser.add_argument("--openssl-tool", default="")
    parser.add_argument("--codesign-tool", default="codesign")
    parser.add_argument(
        "--timestamp-url",
        default="",
        help=(
            "Timestamp authority to countersign with. Empty (the default) "
            "does not timestamp; 'default' selects the well-known authority "
            "for the signer in use; any other value is a server URL."
        ),
    )
    parser.add_argument("--name", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--options", default="")
    parser.add_argument("--entitlements", default="")
    parser.add_argument(
        "--transparency-log",
        default="",
        help=(
            "Rekor instance to publish signatures to. Empty (the default) "
            "publishes nothing and keeps signing offline; 'default' selects "
            "the public Sigstore instance; any other value is the URL of a "
            "specific instance."
        ),
    )

    parser.add_argument("--cert-file", default="")
    parser.add_argument("--ca-file", default="")
    parser.add_argument("--cert-template", default="")
    parser.add_argument("--cert-encoding", choices=("path", "base64"), default="path")
    parser.add_argument("--password-template", default="")
    parser.add_argument("--password-env", default="")
    parser.add_argument("--identity-template", default="")
    parser.add_argument("--stamp-default", action="append", default=[])
    parser.add_argument("--info-file", default="")
    parser.add_argument("--version-file", default="")

    # --mode gen-self-signed
    parser.add_argument("--cert-out", default="")
    parser.add_argument("--public-key-out", default="")
    parser.add_argument("--format", choices=("pem", "p12"), default="pem")
    parser.add_argument("--key-type", choices=("rsa", "ec"), default="rsa")
    parser.add_argument("--key-size", type=int, default=2048)
    parser.add_argument("--ec-curve", default="prime256v1")
    parser.add_argument("--digest", default="sha256")
    parser.add_argument("--validity-days", type=int, default=365)
    parser.add_argument("--common-name", default="")
    parser.add_argument("--organization", default="")
    parser.add_argument("--organizational-unit", default="")
    parser.add_argument("--country", default="")
    parser.add_argument("--state", default="")
    parser.add_argument("--locality", default="")
    parser.add_argument("--email", default="")
    parser.add_argument("--subject-alt-name", action="append", default=[])
    parser.add_argument("--key-usage", action="append", default=[])
    parser.add_argument("--extended-key-usage", action="append", default=[])
    args = parser.parse_args(expand_argfiles(sys.argv[1:]))

    if args.mode == "resolve-cert":
        resolve_cert_mode(args)
        return

    if args.mode == "gen-self-signed":
        gen_self_signed_mode(args)
        return

    sign_mode(args)


if __name__ == "__main__":
    main()
