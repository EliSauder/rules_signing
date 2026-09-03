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
        "pass:{}".format(password),
        "-out",
        str(out),
    ]
    try:
        run_cmd(cmd)
    except subprocess.CalledProcessError:
        # Certificates written by older tools use ciphers that OpenSSL 3 only
        # exposes through its legacy provider.
        run_cmd(cmd + ["-legacy"])
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


def resolve_cert_path(
    *,
    cert_file: str,
    cert_template: str,
    cert_encoding: str,
    stamps: Dict[str, str],
    defaults: Dict[str, str],
    tmpdir: str,
) -> Optional[str]:
    if cert_file:
        return cert_file if pathlib.Path(cert_file).exists() else None

    if not cert_template:
        return None

    rendered = resolve_template(cert_template, stamps, defaults)
    if not rendered:
        return None

    if cert_encoding == "base64":
        out = pathlib.Path(tmpdir) / "cert.bin"
        out.write_bytes(base64.b64decode(rendered.encode("utf-8")))
        return str(out)

    return rendered if pathlib.Path(rendered).exists() else None


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
    if password:
        env["COSIGN_PASSWORD"] = password
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
    """Resolves the root blob of the oci layout using the mainefst digest."""

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
    if password:
        env["COSIGN_PASSWORD"] = password
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
    if name:        cmd.extend(["-n", name])
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
        out_path = pathlib.Path(outdir)
        if out_path.exists():
            shutil.rmtree(out_path)
        sign_with_codesign(
            tool=args.codesign_tool,
            infile=indir,
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

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", choices=("auto", "osslsigncode", "codesign", "cosign"), default="auto")
    parser.add_argument("--in", dest="infile", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--rel", action="append", default=[])
    parser.add_argument("--src", action="append", default=[])

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
    args = parser.parse_args()

    if len(args.rel) != len(args.src):
        raise ValueError("sign_tool: --rel and --src counts must match")

    stamps = load_stamp_files([args.info_file, args.version_file])
    defaults = parse_defaults(args.stamp_default)

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = resolve_cert_path(
            cert_file=args.cert_file,
            cert_template=args.cert_template,
            cert_encoding=args.cert_encoding,
            stamps=stamps,
            defaults=defaults,
            tmpdir=tmpdir,
        )
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

        pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)
        for relpath, src in zip(args.rel, args.src):
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
        return

if __name__ == "__main__":
    main()
