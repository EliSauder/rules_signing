#!/usr/bin/env python3
"""Cross-platform signer orchestration for rules_signing."""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
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

    if not os.path.exists(path):
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


def passthrough(src: str, out: str) -> None:
    """Copies contents of source to out with no modifications"""
    if pathlib.Path(src).is_dir():
        out_path = pathlib.Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_path.exists():
            shutil.rmtree(out_path)
        shutil.copytree(src, out, symlinks=True)
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

def sign_blob_with_cosign(
    *,
    tool: str,
    infile: str,
    outfile: str,
    cert_path: Optional[str],
    password: str,
) -> None:
    passthrough(infile, outfile)
    if not cert_path:
        return
    if not tool:
        raise ValueError("sign_tool: cosign tool path is required for detached signatures")

    env = os.environ.copy()
    if password:
        env["COSIGN_PASSWORD"] = password
    bundle_path = outfile + ".bundle.json"
    signature = run_cmd_capture(
        [tool, "sign-blob", "--yes", "--key", cert_path, "--bundle", bundle_path, infile],
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
    """For oci layout images
    cosign v3 writes the signature only into the Sigstore bundle and
    emits nothing on stdout, get so it from the bundle instead.
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

    run_cmd(
        [
            tool,
            "sign-blob",
            "--yes",
            "--key",
            cert_path,
            "--bundle",
            str(bundle),
            str(root_blob),
        ],
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
) -> None:
    if not cert_path:
        passthrough(infile, outfile)
        return

    ensure_parent(outfile)
    cmd = [tool, "sign", "-pkcs12", cert_path, "-h", "sha256"]
    if password:
        cmd.extend(["-pass", password])
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

    cmd.extend(["--p12-file", cert_path])
    # rcodesign requires the flag even for an empty password.
    cmd.extend(["--p12-password", password or ""])
    if timestamp_url:
        cmd.extend(["--timestamp-url", timestamp_url])
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
) -> None:
    if selected == "osslsigncode":
        sign_with_osslsigncode(
            tool=args.osslsigncode_tool,
            infile=infile,
            outfile=outfile,
            timestamp_url=args.timestamp_url,
            name=args.name,
            url=args.url,
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
            cert_path=cert_path,
            password=password,
            identity=identity,
        )
    elif selected == "cosign":
        sign_blob_with_cosign(
            tool=args.cosign_tool,
            infile=infile,
            outfile=outfile,
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
            cert_path=cert_path,
            password=password,
        )
        return

    if selected == "codesign":
        # macOS bundles (.app/.pkg) are directories, but codesign signs
        # them as a single unit rather than file by file.
        sign_with_codesign(
            tool=args.codesign_tool,
            infile=indir,
            outfile=outdir,
            timestamp_url=args.timestamp_url,
            options=args.options,
            entitlements=args.entitlements,
            cert_path=cert_path,
            password=password,
            identity=identity,
        )
        return

    passthrough(indir, outdir)

    for source_file in pathlib.Path(indir).rglob("*"):
        if not source_file.is_file() or source_file.is_symlink():
            continue
        relative_path = source_file.relative_to(indir).as_posix()
        sign_one(
            tool_mode=tool_mode,
            relpath=relative_path,
            infile=str(source_file),
            outfile=str(pathlib.Path(outdir) / relative_path),
            args=args,
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
            cert_path=cert_path,
            password=password,
        )
        return

    sign_file(
        selected=selected,
        infile=infile,
        outfile=outfile,
        args=args,
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
    parser.add_argument("--codesign-tool", default="codesign")
    parser.add_argument("--timestamp-url", default="")
    parser.add_argument("--name", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--options", default="")
    parser.add_argument("--entitlements", default="")

    parser.add_argument("--cert-file", default="")
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
                cert_path=cert_path,
                password=password,
                identity=identity,
            )
        return

if __name__ == "__main__":
    main()
