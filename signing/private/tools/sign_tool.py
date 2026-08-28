#!/usr/bin/env python3
"""Cross-platform signer orchestration for rules_signing."""

from __future__ import annotations

import argparse
import base64
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
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


def detect_tool(path: str) -> str:
    p = path.lower()
    if p.endswith(_OSSLSIGNCODE_EXT):
        return "osslsigncode"
    if p.endswith(_CODESIGN_EXT):
        return "codesign"
    return ""


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
    ensure_parent(out)
    shutil.copy2(src, out)


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


def run_cmd(cmd: Sequence[str]) -> None:
    subprocess.run(cmd, check=True)


def run_cmd_capture(cmd: Sequence[str]) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def resolve_codesign_identity_from_keychain(keychain: str) -> str:
    output = run_cmd_capture(["security", "find-identity", "-v", "-p", "codesigning", keychain])
    for line in output.splitlines():
        match = re.search(r"\)\s+([0-9A-Fa-f]{40})\s+", line)
        if match:
            return match.group(1)
    raise ValueError("sign_tool: no codesigning identity found in imported certificate")


def setup_codesign_keychain(cert_path: str, password: str, tool: str, tmpdir: str) -> Tuple[str, str]:
    keychain = str(pathlib.Path(tmpdir) / "rules_signing.keychain")
    run_cmd(["security", "create-keychain", "-p", "", keychain])
    run_cmd(["security", "unlock-keychain", "-p", "", keychain])
    import_cmd = ["security", "import", cert_path, "-k", keychain, "-T", tool]
    if password:
        import_cmd.extend(["-P", password])
    run_cmd(import_cmd)
    identity = resolve_codesign_identity_from_keychain(keychain)
    return keychain, identity


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
    selected_identity = identity
    keychain = ""

    if not selected_identity and cert_path:
        if sys.platform != "darwin":
            passthrough(infile, outfile)
            return
        with tempfile.TemporaryDirectory() as keychain_tmp:
            keychain, selected_identity = setup_codesign_keychain(cert_path, password, tool, keychain_tmp)
            passthrough(infile, outfile)
            cmd = [tool, "--force", "--sign", selected_identity]
            if timestamp_url:
                cmd.append("--timestamp={}".format(timestamp_url))
            else:
                cmd.append("--timestamp")
            if options:
                cmd.extend(["--options", options])
            if entitlements:
                cmd.extend(["--entitlements", entitlements])
            cmd.extend(["--keychain", keychain, outfile])
            run_cmd(cmd)
            return

    if not selected_identity:
        passthrough(infile, outfile)
        return

    passthrough(infile, outfile)
    cmd = [tool, "--force", "--sign", selected_identity]
    if timestamp_url:
        cmd.append("--timestamp={}".format(timestamp_url))
    else:
        cmd.append("--timestamp")
    if options:
        cmd.extend(["--options", options])
    if entitlements:
        cmd.extend(["--entitlements", entitlements])
    cmd.append(outfile)
    run_cmd(cmd)


def sign_one(
    *,
    sign_mode: str,
    tool_mode: str,
    relpath: str,
    infile: str,
    outfile: str,
    args: argparse.Namespace,
    cert_path: Optional[str],
    password: str,
    identity: str,
) -> None:
    selected = sign_mode if sign_mode in ("osslsigncode", "codesign") else tool_mode
    if selected == "auto":
        selected = detect_tool(relpath)

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
    else:
        passthrough(infile, outfile)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("tree", "osslsigncode", "codesign"), default="tree")
    parser.add_argument("--tool", choices=("auto", "osslsigncode", "codesign"), default="auto")
    parser.add_argument("--in", dest="infile", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--out-dir", default="")
    parser.add_argument("--rel", action="append", default=[])
    parser.add_argument("--src", action="append", default=[])

    parser.add_argument("--osslsigncode-tool", default="osslsigncode")
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

    if args.mode == "tree" and len(args.rel) != len(args.src):
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

        if args.mode == "tree":
            pathlib.Path(args.out_dir).mkdir(parents=True, exist_ok=True)
            for relpath, src in zip(args.rel, args.src):
                out = str(pathlib.Path(args.out_dir) / relpath)
                sign_one(
                    sign_mode="tree",
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

        if not args.infile or not args.out:
            raise ValueError("sign_tool: --in and --out are required for single-file mode")

        rel = pathlib.Path(args.infile).name
        sign_one(
            sign_mode=args.mode,
            tool_mode=args.tool,
            relpath=rel,
            infile=args.infile,
            outfile=args.out,
            args=args,
            cert_path=cert_path,
            password=password,
            identity=identity,
        )


if __name__ == "__main__":
    main()
