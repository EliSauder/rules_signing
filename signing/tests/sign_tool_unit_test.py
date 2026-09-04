import base64
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from python.runfiles import runfiles

from signing.private.tools import sign_tool

# Certificate formats are distinguished by their PEM armour rather than by
# filename, so fixtures standing in for a PEM must carry the header.
_PEM_CERTIFICATE = (
    "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
    "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
)

# cosign refuses ordinary PEM keys and reads only its own envelope, so keys it
# produced have to be recognised and used as-is rather than re-imported.
_COSIGN_PRIVATE_KEY = (
    "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
    "ZmFrZQ==\n"
    "-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n"
)

# DER, so it never carries PEM armour.
_PKCS12_CERTIFICATE = b"\x30\x82\x0a\x1d\x02\x01\x03\x30\x82\x09\xd7"


def _append_marker(in_path: str, out_path: str, marker: bytes) -> None:
    """Copies a file and appends a marker, byte-safe for real binaries."""
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pathlib.Path(in_path).read_bytes() + marker)


def _fake_run_cmd(cmd: list[str], **_kwargs: object) -> None:
    tool = pathlib.Path(cmd[0]).name
    if tool == "security":
        return
    if "osslsigncode" in tool:
        _append_marker(
            cmd[cmd.index("-in") + 1],
            cmd[cmd.index("-out") + 1],
            b"SIGNED:osslsigncode\n",
        )
        return
    if "cosign" in tool:
        _fake_cosign(cmd)
        return

    # rcodesign: `codesign sign [flags...] <input> <output>`.
    _append_marker(cmd[-2], cmd[-1], b"SIGNED:codesign\n")


def _fake_cosign(cmd: list[str]) -> None:
    """Stands in for the cosign subcommands the signer drives."""
    subcommand = cmd[1]
    if subcommand == "import-key-pair":
        # cosign rewraps the supplied key into its own envelope, writing
        # <prefix>.key and <prefix>.pub.
        prefix = pathlib.Path(cmd[cmd.index("--output-key-prefix") + 1])
        prefix.with_suffix(".key").write_text(
            _COSIGN_PRIVATE_KEY, encoding="utf-8"
        )
        prefix.with_suffix(".pub").write_text("PUBLIC\n", encoding="utf-8")
        return
    if subcommand == "signing-config":
        # Real cosign records the rekor service in the config it writes, so the
        # stub does too; otherwise nothing downstream could tell the settings
        # apart.
        config = {}
        if "--rekor" in cmd:
            spec = cmd[cmd.index("--rekor") + 1]
            config["rekor"] = dict(
                kv.split("=", 1) for kv in spec.split(",")
            )["url"]
        pathlib.Path(cmd[cmd.index("--out") + 1]).write_text(
            json.dumps(config), encoding="utf-8"
        )
        return

    bundle = pathlib.Path(cmd[cmd.index("--bundle") + 1])
    bundle.write_text('{"signature":"detached"}\n', encoding="utf-8")


def _fake_run_cmd_capture(cmd: list[str], **_kwargs: object) -> str:
    # Mirrors cosign v3: the signature is written only into the Sigstore
    # bundle and nothing is emitted on stdout.
    bundle = pathlib.Path(cmd[cmd.index("--bundle") + 1])
    bundle.write_text(
        json.dumps({"messageSignature": {"signature": "detached-signature"}}),
        encoding="utf-8",
    )
    return ""


def _binary_fixtures() -> "tuple[str, str]":
    """Paths to the cross-compiled Mach-O and PE fixtures."""
    r = runfiles.Create()
    paths = []
    for name in ("hello_macho", "hello_pe"):
        path = r.Rlocation("rules_signing/signing/tests/" + name)
        assert path and pathlib.Path(path).is_file(), "missing fixture: " + name
        paths.append(path)
    return paths[0], paths[1]


class SignToolUnitTest(unittest.TestCase):
    def _args(self):
        class Args:
            osslsigncode_tool = "fake-osslsigncode"
            cosign_tool = "fake-cosign"
            codesign_tool = "fake-codesign"
            timestamp_url = "https://timestamp.example.invalid"
            name = "Example"
            url = "https://example.invalid"
            options = "runtime"
            entitlements = ""
            tool = "auto"
            transparency_log = ""
            ca_file = ""
            openssl_tool = ""

        return Args()

    def test_detect_tool(self) -> None:
        self.assertEqual(sign_tool.detect_tool("bin/App.EXE"), "osslsigncode")
        self.assertEqual(sign_tool.detect_tool("dist/image.dmg"), "codesign")
        self.assertEqual(sign_tool.detect_tool("notes/readme.txt"), "cosign")

    def test_detect_tool_sniffs_extensionless_binaries(self) -> None:
        # Real cross-compiled executables, passed as runfiles. Both have no
        # extension, so only the header can identify them.
        macho, pe = _binary_fixtures()

        self.assertEqual(sign_tool.sniff_binary_format(macho), "codesign")
        self.assertEqual(sign_tool.detect_tool("bin/hello_macho", macho), "codesign")

        self.assertEqual(sign_tool.sniff_binary_format(pe), "osslsigncode")
        self.assertEqual(sign_tool.detect_tool("bin/hello_pe", pe), "osslsigncode")

        with tempfile.TemporaryDirectory() as tmp:
            # Non-signable extensionless content still falls back to cosign.
            text = pathlib.Path(tmp) / "LICENSE"
            text.write_text("plain text\n", encoding="utf-8")
            self.assertEqual(sign_tool.sniff_binary_format(str(text)), "")
            self.assertEqual(sign_tool.detect_tool("LICENSE", str(text)), "cosign")

    def test_detect_tool_prefers_extension_over_contents(self) -> None:
        # An explicit extension stays authoritative even if the bytes disagree.
        _, pe = _binary_fixtures()
        self.assertEqual(sign_tool.detect_tool("installer.dmg", pe), "codesign")

    def test_sniff_binary_format_tolerates_unreadable_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(sign_tool.sniff_binary_format(str(pathlib.Path(tmp) / "missing")), "")
            # Directories (e.g. .app bundles) must not raise.
            self.assertEqual(sign_tool.sniff_binary_format(tmp), "")

    def test_extensionless_binaries_in_a_directory_pick_their_own_tool(self) -> None:
        macho, pe = _binary_fixtures()

        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd),
            mock.patch.object(sign_tool, "run_cmd_capture", side_effect=_fake_run_cmd_capture),
        ):
            root = pathlib.Path(tmp)
            source = root / "in"
            (source / "bin").mkdir(parents=True)
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            shutil.copy(macho, source / "bin" / "mactool")
            shutil.copy(pe, source / "bin" / "wintool")
            (source / "bin" / "README").write_text("docs", encoding="utf-8")

            sign_tool.sign_one(
                tool_mode="auto",
                relpath="",
                infile=str(source),
                outfile=str(root / "out"),
                args=self._args(),
                cert_path=str(cert),
                password="",
                identity="",
            )

            out = root / "out" / "bin"
            self.assertIn(b"SIGNED:codesign", (out / "mactool").read_bytes())
            self.assertIn(b"SIGNED:osslsigncode", (out / "wintool").read_bytes())
            self.assertTrue((out / "README.sig").is_file())
            # Natively signed binaries must not also get detached sidecars.
            self.assertFalse((out / "mactool.sig").exists())
            self.assertFalse((out / "wintool.sig").exists())

    def test_interpolate_template(self) -> None:
        value, unresolved = sign_tool.interpolate_template(
            "prefix-{A}-{B}-suffix",
            stamps={"A": "one"},
            defaults={"B": "two"},
        )
        self.assertEqual(value, "prefix-one-two-suffix")
        self.assertFalse(unresolved)

    def test_interpolate_template_unresolved(self) -> None:
        value, unresolved = sign_tool.interpolate_template(
            "{A}-{B}",
            stamps={"A": "one"},
            defaults={},
        )
        self.assertEqual(value, "one-")
        self.assertTrue(unresolved)
        self.assertIsNone(sign_tool.resolve_template("{A}-{B}", {"A": "one"}, {}))

    def test_certificate_template_resolution_permutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            cert_file = tmp_path / "cert.p12"
            cert_file.write_text("cert", encoding="utf-8")

            # Direct file: `resolve_cert_path` only ever sees an already
            # resolved file (the `certificate` rule handles templates via
            # `render_cert_material` before `sign` ever runs).
            resolved = sign_tool.resolve_cert_path(cert_file=str(cert_file))
            self.assertEqual(resolved, str(cert_file))

            # An empty file is the sentinel written when a template could not
            # be resolved to real material; treated the same as no cert.
            empty_file = tmp_path / "empty.bin"
            empty_file.write_bytes(b"")
            self.assertIsNone(sign_tool.resolve_cert_path(cert_file=str(empty_file)))
            self.assertIsNone(sign_tool.resolve_cert_path(cert_file=""))

            # Template path, resolved by `render_cert_material` (what the
            # `certificate` rule's `resolve-cert` action runs).
            data, unresolved = sign_tool.render_cert_material(
                cert_template="{CERT_PATH}",
                cert_encoding="path",
                stamps={},
                defaults={"CERT_PATH": str(cert_file)},
            )
            self.assertFalse(unresolved)
            self.assertEqual(data, b"cert")

            # Template path that does not exist on disk: tolerated (not an
            # error), rendered as `None` so the resolver writes the empty
            # sentinel file instead of failing the build.
            data, unresolved = sign_tool.render_cert_material(
                cert_template="{CERT_PATH}",
                cert_encoding="path",
                stamps={},
                defaults={"CERT_PATH": str(tmp_path / "missing.p12")},
            )
            self.assertFalse(unresolved)
            self.assertIsNone(data)

            # Template base64.
            data, unresolved = sign_tool.render_cert_material(
                cert_template="{CERT_B64}",
                cert_encoding="base64",
                stamps={},
                defaults={"CERT_B64": "Y2VydC1iYXNlNjQ="},
            )
            self.assertFalse(unresolved)
            self.assertEqual(data, b"cert-base64")

            # Unresolved placeholder: always a hard error, regardless of
            # encoding.
            data, unresolved = sign_tool.render_cert_material(
                cert_template="{MISSING_KEY}",
                cert_encoding="base64",
                stamps={},
                defaults={},
            )
            self.assertTrue(unresolved)
            self.assertIsNone(data)

    def test_password_and_identity_resolution_permutations(self) -> None:
        with mock.patch.dict("os.environ", {"CERT_PASSWORD_ENV": "from-env"}, clear=False):
            self.assertEqual(
                sign_tool.resolve_password(
                    password_template="{PWD}",
                    password_env="CERT_PASSWORD_ENV",
                    stamps={"PWD": "from-template"},
                    defaults={},
                ),
                "from-template",
            )
            self.assertEqual(
                sign_tool.resolve_password(
                    password_template="",
                    password_env="CERT_PASSWORD_ENV",
                    stamps={},
                    defaults={},
                ),
                "from-env",
            )
        self.assertEqual(
            sign_tool.resolve_identity(
                identity_template="{IDENTITY}",
                stamps={},
                defaults={"IDENTITY": "Developer ID Application: Example"},
            ),
            "Developer ID Application: Example",
        )

    def test_single_files_use_native_or_detached_signatures(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd),
            mock.patch.object(sign_tool, "run_cmd_capture", side_effect=_fake_run_cmd_capture),
        ):
            root = pathlib.Path(tmp)
            in_exe = root / "in" / "bin" / "app.exe"
            in_dmg = root / "in" / "mac" / "app.dmg"
            in_txt = root / "in" / "docs" / "readme.txt"
            out_root = root / "out"
            cert = root / "cert.pem"

            in_exe.parent.mkdir(parents=True, exist_ok=True)
            in_dmg.parent.mkdir(parents=True, exist_ok=True)
            in_txt.parent.mkdir(parents=True, exist_ok=True)
            in_exe.write_text("EXE\n", encoding="utf-8")
            in_dmg.write_text("DMG\n", encoding="utf-8")
            in_txt.write_text("TXT\n", encoding="utf-8")
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            args = self._args()
            sign_tool.sign_one(
                tool_mode="auto",
                relpath="bin/app.exe",
                infile=str(in_exe),
                outfile=str(out_root / "bin" / "app.exe"),
                args=args,
                cert_path=str(cert),
                password="pw",
                identity="Developer ID",
            )
            sign_tool.sign_one(
                tool_mode="auto",
                relpath="mac/app.dmg",
                infile=str(in_dmg),
                outfile=str(out_root / "mac" / "app.dmg"),
                args=args,
                cert_path=str(cert),
                password="pw",
                identity="Developer ID",
            )
            sign_tool.sign_one(
                tool_mode="auto",
                relpath="docs/readme.txt",
                infile=str(in_txt),
                outfile=str(out_root / "docs" / "readme.txt"),
                args=args,
                cert_path=str(cert),
                password="pw",
                identity="Developer ID",
            )

            self.assertIn("SIGNED:osslsigncode", (out_root / "bin" / "app.exe").read_text(encoding="utf-8"))
            self.assertIn("SIGNED:codesign", (out_root / "mac" / "app.dmg").read_text(encoding="utf-8"))
            self.assertEqual((out_root / "docs" / "readme.txt").read_text(encoding="utf-8"), "TXT\n")
            self.assertEqual((out_root / "docs" / "readme.txt.sig").read_text(encoding="utf-8"), "detached-signature\n")
            self.assertTrue((out_root / "docs" / "readme.txt.bundle.json").is_file())

    def test_multiple_files_are_all_returned_with_detached_signatures(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sign_tool, "run_cmd_capture", side_effect=_fake_run_cmd_capture),
        ):
            root = pathlib.Path(tmp)
            inputs = [root / "in" / "one.txt", root / "in" / "two.tar.gz"]
            cert = root / "key.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            for input_file in inputs:
                input_file.parent.mkdir(parents=True, exist_ok=True)
                input_file.write_text(input_file.name, encoding="utf-8")
                sign_tool.sign_one(
                    tool_mode="auto",
                    relpath=input_file.name,
                    infile=str(input_file),
                    outfile=str(root / "out" / input_file.name),
                    args=self._args(),
                    cert_path=str(cert),
                    password="",
                    identity="",
                )

            self.assertEqual(
                {path.name for path in (root / "out").iterdir()},
                {"one.txt", "one.txt.sig", "one.txt.bundle.json", "two.tar.gz", "two.tar.gz.sig", "two.tar.gz.bundle.json"},
            )

    def test_non_oci_directory_preserves_layout_and_signs_each_file(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd),
            mock.patch.object(sign_tool, "run_cmd_capture", side_effect=_fake_run_cmd_capture),
        ):
            root = pathlib.Path(tmp)
            source = root / "in"
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            for relative_path in ["bin/app.exe", "lib/helper.dll", "docs/readme.txt"]:
                path = source / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative_path, encoding="utf-8")

            sign_tool.sign_one(
                tool_mode="auto",
                relpath="",
                infile=str(source),
                outfile=str(root / "out"),
                args=self._args(),
                cert_path=str(cert),
                password="",
                identity="",
            )

            output = root / "out"
            self.assertIn("SIGNED:osslsigncode", (output / "bin" / "app.exe").read_text(encoding="utf-8"))
            self.assertIn("SIGNED:osslsigncode", (output / "lib" / "helper.dll").read_text(encoding="utf-8"))
            self.assertEqual((output / "docs" / "readme.txt").read_text(encoding="utf-8"), "docs/readme.txt")
            self.assertTrue((output / "docs" / "readme.txt.sig").is_file())
            self.assertTrue((output / "docs" / "readme.txt.bundle.json").is_file())

            # Natively signed artifacts must not gain detached sidecars.
            self.assertFalse((output / "bin" / "app.exe.sig").exists())
            self.assertFalse((output / "bin" / "app.exe.bundle.json").exists())
            self.assertFalse((output / "lib" / "helper.dll.sig").exists())

            # The detached signature must carry the real signature bytes.
            self.assertEqual(
                (output / "docs" / "readme.txt.sig").read_text(encoding="utf-8").strip(),
                "detached-signature",
            )

    def test_mixed_directory_signs_each_file_with_its_own_tool(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd),
            mock.patch.object(sign_tool, "run_cmd_capture", side_effect=_fake_run_cmd_capture),
        ):
            root = pathlib.Path(tmp)
            source = root / "in"
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            natively_signed = ["bin/app.exe", "bin/tool.dll"]
            detached_signed = ["bin/notes.txt", "docs/readme.txt", "config.yaml"]
            for relative_path in natively_signed + detached_signed:
                path = source / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative_path, encoding="utf-8")

            sign_tool.sign_one(
                tool_mode="auto",
                relpath="",
                infile=str(source),
                outfile=str(root / "out"),
                args=self._args(),
                cert_path=str(cert),
                password="",
                identity="",
            )

            output = root / "out"
            for relative_path in natively_signed:
                signed = output / relative_path
                self.assertIn("SIGNED:osslsigncode", signed.read_text(encoding="utf-8"))
                self.assertFalse(signed.with_suffix(signed.suffix + ".sig").exists())

            for relative_path in detached_signed:
                original = output / relative_path
                self.assertEqual(original.read_text(encoding="utf-8"), relative_path)
                signature = output / (relative_path + ".sig")
                self.assertTrue(signature.is_file())
                self.assertEqual(signature.read_text(encoding="utf-8").strip(), "detached-signature")
                self.assertTrue((output / (relative_path + ".bundle.json")).is_file())

            # A PE file and a text file living side by side in one directory
            # must both be signed, each with its own mechanism.
            self.assertIn("SIGNED:osslsigncode", (output / "bin" / "app.exe").read_text(encoding="utf-8"))
            self.assertTrue((output / "bin" / "notes.txt.sig").is_file())

    def test_read_signature_from_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = pathlib.Path(tmp) / "b.json"

            bundle.write_text(
                json.dumps({"messageSignature": {"signature": "abc123"}}), encoding="utf-8"
            )
            self.assertEqual(sign_tool.read_signature_from_bundle(str(bundle)), "abc123")

            bundle.write_text(json.dumps({"base64Signature": "legacy"}), encoding="utf-8")
            self.assertEqual(sign_tool.read_signature_from_bundle(str(bundle)), "legacy")

            bundle.write_text("not json", encoding="utf-8")
            self.assertEqual(sign_tool.read_signature_from_bundle(str(bundle)), "")

            self.assertEqual(sign_tool.read_signature_from_bundle(str(bundle) + ".missing"), "")

    def test_oci_layout_returns_image_and_signature_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd):
            root = pathlib.Path(tmp)
            source = root / "image"
            digest = "a" * 64
            blob = source / "blobs" / "sha256" / digest
            blob.parent.mkdir(parents=True, exist_ok=True)
            blob.write_text("manifest", encoding="utf-8")
            (source / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
            (source / "index.json").write_text(
                json.dumps({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + digest}]}),
                encoding="utf-8",
            )
            cert = root / "key.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            sign_tool.sign_one(
                tool_mode="auto",
                relpath="",
                infile=str(source),
                outfile=str(root / "out"),
                args=self._args(),
                cert_path=str(cert),
                password="",
                identity="",
            )

            output = root / "out"
            self.assertTrue(sign_tool.is_oci_layout(str(output)))
            self.assertEqual((output / "blobs" / "sha256" / digest).read_text(encoding="utf-8"), "manifest")
            self.assertTrue((output / "signatures" / (digest + ".bundle.json")).is_file())

    def test_codesign_uses_certificate_and_runs_off_macos(self) -> None:
        # codesign.bzl ships rcodesign prebuilts for Linux/Windows/macOS, so
        # signing must work regardless of host platform and must never silently
        # fall back to a detached signature.
        for platform in ("linux", "win32", "darwin"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                in_dmg = root / "in" / "mac" / "app.dmg"
                out_dmg = root / "out" / "mac" / "app.dmg"
                cert = root / "cert.p12"

                in_dmg.parent.mkdir(parents=True, exist_ok=True)
                in_dmg.write_text("DMG\n", encoding="utf-8")
                cert.write_text("CERT\n", encoding="utf-8")

                recorded: list[list[str]] = []

                def _record(cmd: list[str], **kwargs: object) -> None:
                    recorded.append(cmd)
                    _fake_run_cmd(cmd, **kwargs)

                with (
                    mock.patch.object(sign_tool, "run_cmd", side_effect=_record),
                    mock.patch("sys.platform", platform),
                ):
                    sign_tool.sign_one(
                        tool_mode="auto",
                        relpath="mac/app.dmg",
                        infile=str(in_dmg),
                        outfile=str(out_dmg),
                        args=self._args(),
                        cert_path=str(cert),
                        password="secret",
                        identity="",
                    )

                self.assertIn("SIGNED:codesign", out_dmg.read_text(encoding="utf-8"))
                self.assertFalse(out_dmg.with_suffix(".dmg.sig").exists())

                self.assertEqual(len(recorded), 1)
                cmd = recorded[0]
                self.assertEqual(cmd[1], "sign")
                self.assertEqual(cmd[cmd.index("--p12-file") + 1], str(cert))
                self.assertEqual(cmd[cmd.index("--p12-password") + 1], "secret")
                self.assertEqual(cmd[-2:], [str(in_dmg), str(out_dmg)])
                # rcodesign needs no keychain, so `security` must never be run.
                self.assertNotIn("security", [pathlib.Path(c[0]).name for c in recorded])

    def test_codesign_uses_pem_certificate_without_p12_flags(self) -> None:
        # A unified PEM (certificate plus unencrypted key) is read directly via
        # --pem-file instead of being forced through --p12-file.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            infile = root / "in" / "app.dmg"
            outfile = root / "out" / "app.dmg"
            cert = root / "cert.pem"

            infile.parent.mkdir(parents=True, exist_ok=True)
            infile.write_text("DMG\n", encoding="utf-8")
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            recorded: list[list[str]] = []
            with mock.patch.object(sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)):
                sign_tool.sign_with_codesign(
                    tool="fake-codesign",
                    infile=str(infile),
                    outfile=str(outfile),
                    timestamp_url="",
                    options="runtime",
                    entitlements="",
                    cert_path=str(cert),
                    password="",
                    identity="com.rulessigning.test",
                )

            self.assertEqual(len(recorded), 1)
            cmd = recorded[0]
            self.assertEqual(cmd[cmd.index("--pem-file") + 1], str(cert))
            self.assertNotIn("--p12-file", cmd)
            self.assertNotIn("--p12-password", cmd)
            self.assertEqual(cmd[cmd.index("--binary-identifier") + 1], "com.rulessigning.test")

    def test_codesign_directory_replaces_existing_output_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "hello.app"
            (source / "Contents").mkdir(parents=True)
            info_plist = source / "Contents" / "Info.plist"
            info_plist.write_text("plist", encoding="utf-8")
            info_plist.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            output = root / "out"
            output.mkdir(parents=True)
            (output / "stale.txt").write_text("stale", encoding="utf-8")

            recorded: list[list[str]] = []

            def _fake_codesign_directory(cmd: list[str], **_kwargs: object) -> None:
                recorded.append(cmd)
                staged_info = pathlib.Path(cmd[-2]) / "Contents" / "Info.plist"
                self.assertTrue(staged_info.is_file())
                self.assertTrue(os.access(staged_info, os.W_OK))
                shutil.copytree(cmd[-2], cmd[-1], symlinks=False)

            args = self._args()
            args.tool = "codesign"
            with mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_codesign_directory):
                sign_tool.sign_one(
                    tool_mode="codesign",
                    relpath="",
                    infile=str(source),
                    outfile=str(output),
                    args=args,
                    cert_path=str(cert),
                    password="",
                    identity="dev.rules-signing.hello",
                )

            self.assertEqual(len(recorded), 1)
            self.assertFalse((output / "stale.txt").exists())
            self.assertTrue((output / "Contents" / "Info.plist").is_file())
            self.assertNotEqual(recorded[0][-2], str(source))
            self.assertEqual(recorded[0][-1], str(output))

    def test_osslsigncode_uses_pem_certificate_without_pkcs12_flags(self) -> None:
        # A unified PEM (certificate plus unencrypted key) is read via
        # -certs/-key instead of being forced through -pkcs12/-pass.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            infile = root / "in" / "app.exe"
            outfile = root / "out" / "app.exe"
            cert = root / "cert.pem"

            infile.parent.mkdir(parents=True, exist_ok=True)
            infile.write_text("EXE\n", encoding="utf-8")
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            recorded: list[list[str]] = []
            with mock.patch.object(sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)):
                sign_tool.sign_with_osslsigncode(
                    tool="fake-osslsigncode",
                    infile=str(infile),
                    outfile=str(outfile),
                    timestamp_url="",
                    name="rules_signing test description",
                    url="https://example.invalid/publisher",
                    cert_path=str(cert),
                    password="",
                )

            self.assertEqual(len(recorded), 1)
            cmd = recorded[0]
            self.assertEqual(cmd[cmd.index("-certs") + 1], str(cert))
            self.assertEqual(cmd[cmd.index("-key") + 1], str(cert))
            self.assertNotIn("-pkcs12", cmd)
            self.assertNotIn("-pass", cmd)
            self.assertEqual(cmd[cmd.index("-n") + 1], "rules_signing test description")
            self.assertEqual(cmd[cmd.index("-i") + 1], "https://example.invalid/publisher")

    def test_codesign_requires_a_resolved_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            in_dmg = root / "app.dmg"
            in_dmg.write_text("DMG\n", encoding="utf-8")

            args = self._args()
            args.codesign_tool = ""

            with self.assertRaises(ValueError) as ctx:
                sign_tool.sign_one(
                    tool_mode="auto",
                    relpath="app.dmg",
                    infile=str(in_dmg),
                    outfile=str(root / "out" / "app.dmg"),
                    args=args,
                    cert_path="",
                    password="",
                    identity="",
                )
            self.assertIn("codesign tool path is required", str(ctx.exception))

    def test_tree_mode_preserves_relative_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src_root = root / "src"
            out_root = root / "out"
            rels = ["a/b/c.txt", "docs/readme.txt", "bin/tool.exe"]
            for rel in rels:
                p = src_root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(rel + "\n", encoding="utf-8")
                sign_tool.passthrough(str(p), str(out_root / rel))

            out_rels = {p.relative_to(out_root).as_posix() for p in out_root.rglob("*") if p.is_file()}
            self.assertEqual(out_rels, set(rels))

    def test_certificate_format_is_detected_from_content_not_filename(self) -> None:
        # Certificates do not always arrive with a meaningful name: a base64
        # certificate is decoded into a scratch file, and a stamped path can
        # point anywhere. Only the contents can be relied on.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)

            pem_without_extension = root / "cert.bin"
            pem_without_extension.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            self.assertTrue(sign_tool.is_pem_certificate(str(pem_without_extension)))

            # PKCS#12 is DER, which never begins with PEM armour.
            pkcs12_named_pem = root / "cert.pem"
            pkcs12_named_pem.write_bytes(b"\x30\x82\x0a\x1d\x02\x01\x03\x30\x82")
            self.assertFalse(sign_tool.is_pem_certificate(str(pkcs12_named_pem)))

            self.assertFalse(sign_tool.is_pem_certificate(str(root / "missing")))

    def test_base64_certificate_is_signed_as_pkcs12(self) -> None:
        # The decoded file is named cert.bin, so treating it as a PEM purely
        # because of its extension would break the base64 encoding mode.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            infile = root / "app.exe"
            infile.write_text("EXE\n", encoding="utf-8")

            der = b"\x30\x82\x0a\x1d\x02\x01\x03"
            data, unresolved = sign_tool.render_cert_material(
                cert_template=base64.b64encode(der).decode("ascii"),
                cert_encoding="base64",
                stamps={},
                defaults={},
            )
            self.assertFalse(unresolved)
            cert_path = str(root / "cert.bin")
            pathlib.Path(cert_path).write_bytes(data)
            self.assertEqual(pathlib.Path(cert_path).read_bytes(), der)

            recorded: list[list[str]] = []
            with mock.patch.object(
                sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)
            ):
                sign_tool.sign_with_osslsigncode(
                    tool="fake-osslsigncode",
                    infile=str(infile),
                    outfile=str(root / "out.exe"),
                    timestamp_url="",
                    name="",
                    url="",
                    cert_path=cert_path,
                    password="secret",
                )

            cmd = recorded[0]
            self.assertEqual(cmd[cmd.index("-pkcs12") + 1], cert_path)
            self.assertEqual(cmd[cmd.index("-pass") + 1], "secret")
            self.assertNotIn("-certs", cmd)

    def _signing_config_cmd(self, tmp, transparency_log):
        """Returns the `signing-config create` cosign was asked to run."""
        recorded = []

        def fake_run_cmd(cmd, **_kwargs):
            recorded.append(cmd)
            pathlib.Path(cmd[cmd.index("--out") + 1]).write_text("{}", encoding="utf-8")

        with mock.patch.object(sign_tool, "run_cmd", side_effect=fake_run_cmd):
            cmd = sign_tool.cosign_sign_blob_cmd(
                tool="fake-cosign",
                cert_path="cosign.key",
                bundle_path="out.bundle.json",
                infile="blob.txt",
                tmpdir=tmp,
                transparency_log=transparency_log,
            )

        self.assertEqual(recorded[0][1:3], ["signing-config", "create"])
        config = cmd[cmd.index("--signing-config") + 1]
        self.assertTrue(pathlib.Path(config).is_file())
        self.assertEqual(cmd[-1], "blob.txt")
        return recorded[0]

    def test_transparency_log_is_off_by_default(self) -> None:
        # cosign uploads to the public Rekor log unless handed a signing config
        # saying otherwise, so an unset transparency_log must still produce a
        # config -- one naming no services at all.
        with tempfile.TemporaryDirectory() as tmp:
            create = self._signing_config_cmd(tmp, "")
            self.assertNotIn("--rekor", create)

    def test_transparency_log_default_selects_the_public_instance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            create = self._signing_config_cmd(tmp, "default")
            spec = create[create.index("--rekor") + 1]
            self.assertIn("url=https://rekor.sigstore.dev", spec)
            self.assertEqual(create[create.index("--rekor-config") + 1], "ANY")

    def test_transparency_log_accepts_a_private_instance_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            create = self._signing_config_cmd(tmp, "https://rekor.internal.example")
            spec = create[create.index("--rekor") + 1]
            self.assertIn("url=https://rekor.internal.example", spec)

            # The operator is a required key, and defaulting it to the host
            # keeps a private deployment from being labelled as sigstore.dev.
            self.assertIn("operator=rekor.internal.example", spec)
            self.assertNotIn("sigstore.dev", spec)

    def _codesign_cmd(self, timestamp_url):
        """Runs sign_with_codesign and returns the rcodesign argv."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "hello"
            src.write_bytes(b"binary")
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            recorded = []

            def fake(cmd, **_kwargs):
                recorded.append(cmd)

            with mock.patch.object(sign_tool, "run_cmd", side_effect=fake):
                sign_tool.sign_with_codesign(
                    tool="fake-codesign",
                    infile=str(src),
                    outfile=str(root / "out"),
                    timestamp_url=timestamp_url,
                    options="",
                    entitlements="",
                    cert_path=str(cert),
                    password="",
                    identity="",
                )
            return recorded[0]

    def _osslsigncode_cmd(self, timestamp_url):
        """Runs sign_with_osslsigncode and returns the argv."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "app.exe"
            src.write_bytes(b"MZ")
            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            recorded = []

            def fake(cmd, **_kwargs):
                recorded.append(cmd)

            with mock.patch.object(sign_tool, "run_cmd", side_effect=fake):
                sign_tool.sign_with_osslsigncode(
                    tool="fake-osslsigncode",
                    infile=str(src),
                    outfile=str(root / "out.exe"),
                    timestamp_url=timestamp_url,
                    name="",
                    url="",
                    cert_path=str(cert),
                    password="",
                )
            return recorded[0]

    def test_timestamping_is_off_by_default(self) -> None:
        # rcodesign countersigns against Apple's server unless it is actively
        # told not to, so leaving timestamp_url unset must still produce the
        # flag that disables it. Omitting the flag would make the default a
        # silent network call to Apple on every build.
        cmd = self._codesign_cmd("")
        self.assertEqual(cmd[cmd.index("--timestamp-url") + 1], "none")

        # osslsigncode does not timestamp unless asked, so nothing is needed.
        self.assertNotIn("-t", self._osslsigncode_cmd(""))

    def test_timestamp_url_default_selects_each_signers_authority(self) -> None:
        cmd = self._codesign_cmd("default")
        self.assertEqual(
            cmd[cmd.index("--timestamp-url") + 1],
            "http://timestamp.apple.com/ts01",
        )

        cmd = self._osslsigncode_cmd("default")
        self.assertEqual(cmd[cmd.index("-t") + 1], "http://timestamp.digicert.com")

    def test_timestamp_url_accepts_a_specific_server(self) -> None:
        url = "http://tsa.internal.example/ts"
        cmd = self._codesign_cmd(url)
        self.assertEqual(cmd[cmd.index("--timestamp-url") + 1], url)

        cmd = self._osslsigncode_cmd(url)
        self.assertEqual(cmd[cmd.index("-t") + 1], url)

    def test_timestamp_url_rejects_a_value_that_is_not_a_url(self) -> None:
        # "none" used to be the way to disable timestamping, but it is
        # rcodesign-specific: osslsigncode would treat it as a real hostname
        # and fail. Blank is now the way to say that, so the old spelling has
        # to be rejected rather than silently passed through.
        for value in ("none", "true", "timestamp.digicert.com"):
            with self.subTest(value=value):
                for signer in ("codesign", "osslsigncode"):
                    with self.assertRaises(ValueError) as caught:
                        sign_tool.resolve_timestamp_url(value, signer)
                    self.assertIn("timestamp_url", str(caught.exception))

    def test_transparency_log_rejects_a_value_that_is_not_a_url(self) -> None:
        # "true" is the obvious thing to try for what used to be a boolean, and
        # silently treating it as a URL would fail deep inside cosign.
        for value in ("true", "yes", "rekor.sigstore.dev"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    sign_tool.resolve_rekor_url(value)
                self.assertIn("transparency_log", str(caught.exception))

    def test_transparency_log_settings_do_not_share_a_cached_config(self) -> None:
        # The config is cached per tmpdir, so two settings resolving to the
        # same file would silently publish to the wrong place.
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_cosign):
                offline = sign_tool.cosign_signing_config("fake-cosign", tmp, "")
                public = sign_tool.cosign_signing_config("fake-cosign", tmp, "default")
                private = sign_tool.cosign_signing_config(
                    "fake-cosign", tmp, "https://rekor.internal.example"
                )
        self.assertEqual(len({offline, public, private}), 3)

    def test_signing_a_blob_passes_the_signing_config_through(self) -> None:
        """The config reaches the real signing path, not just the command builder."""

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            blob = root / "blob.txt"
            blob.write_text("payload", encoding="utf-8")
            key = root / "cosign.key"
            key.write_text(_COSIGN_PRIVATE_KEY, encoding="utf-8")
            recorded = []

            def capture(cmd, **kwargs):
                recorded.append(cmd)
                return _fake_run_cmd_capture(cmd, **kwargs)

            with mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_cosign), \
                 mock.patch.object(sign_tool, "run_cmd_capture", side_effect=capture):
                sign_tool.sign_blob_with_cosign(
                    tool="fake-cosign",
                    infile=str(blob),
                    outfile=str(root / "out.txt"),
                    cert_path=str(key),
                    password="",
                    tmpdir=tmp,
                    transparency_log="https://rekor.internal.example",
                )

            self.assertIn("--signing-config", recorded[0])
            config = json.loads(
                pathlib.Path(recorded[0][recorded[0].index("--signing-config") + 1])
                .read_text(encoding="utf-8")
            )
            self.assertEqual(config["rekor"], "https://rekor.internal.example")

    def test_directory_contents_are_signed_even_when_staged_as_symlinks(self) -> None:
        # Bazel stages the contents of a directory input as symlinks into the
        # execroot. Skipping symlinks would leave every file in the directory
        # silently unsigned.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            real = root / "real"
            real.mkdir()
            (real / "readme.txt").write_text("payload\n", encoding="utf-8")

            staged = root / "staged"
            (staged / "docs").mkdir(parents=True)
            (staged / "docs" / "readme.txt").symlink_to(real / "readme.txt")

            cert = root / "cert.pem"
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")

            out = root / "out"
            with mock.patch.object(sign_tool, "run_cmd", _fake_run_cmd), mock.patch.object(
                sign_tool, "run_cmd_capture", _fake_run_cmd_capture
            ):
                sign_tool.sign_one(
                    tool_mode="auto",
                    relpath="",
                    infile=str(staged),
                    outfile=str(out),
                    args=self._args(),
                    cert_path=str(cert),
                    password="",
                    identity="",
                )

            signed = out / "docs" / "readme.txt"
            self.assertTrue(signed.is_file())

            # The copy must be a real file, not a symlink back into the input,
            # which would not outlive the action that produced it.
            self.assertFalse(signed.is_symlink())
            self.assertTrue((out / "docs" / "readme.txt.sig").is_file())

    # ------------------------------------------------------------------
    # Credential handling: which flags each signer receives for each of the
    # certificate formats a `certificate()` target can produce.
    # ------------------------------------------------------------------

    def _cert(self, root: pathlib.Path, name: str, pem: bool) -> pathlib.Path:
        cert = root / name
        if pem:
            cert.write_text(_PEM_CERTIFICATE, encoding="utf-8")
        else:
            cert.write_bytes(_PKCS12_CERTIFICATE)
        return cert

    def test_osslsigncode_credential_flags_per_certificate_format(self) -> None:
        for pem, expected, forbidden in (
            (True, ["-certs", "-key"], ["-pkcs12", "-pass"]),
            (False, ["-pkcs12", "-pass"], ["-certs", "-key"]),
        ):
            with self.subTest(pem=pem), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                infile = root / "app.exe"
                infile.write_text("EXE\n", encoding="utf-8")
                cert = self._cert(root, "cert.bin", pem)

                recorded: list[list[str]] = []
                with mock.patch.object(
                    sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)
                ):
                    sign_tool.sign_with_osslsigncode(
                        tool="fake-osslsigncode",
                        infile=str(infile),
                        outfile=str(root / "out.exe"),
                        timestamp_url="",
                        name="",
                        url="",
                        cert_path=str(cert),
                        password="secret",
                    )

                cmd = recorded[0]
                for flag in expected:
                    self.assertIn(flag, cmd)
                for flag in forbidden:
                    self.assertNotIn(flag, cmd)

    def test_codesign_credential_flags_per_certificate_format(self) -> None:
        for pem, expected, forbidden in (
            (True, ["--pem-file"], ["--p12-file", "--p12-password"]),
            (False, ["--p12-file", "--p12-password"], ["--pem-file"]),
        ):
            with self.subTest(pem=pem), tempfile.TemporaryDirectory() as tmp:
                root = pathlib.Path(tmp)
                infile = root / "app.dmg"
                infile.write_text("DMG\n", encoding="utf-8")
                cert = self._cert(root, "cert.bin", pem)

                recorded: list[list[str]] = []
                with mock.patch.object(
                    sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)
                ):
                    sign_tool.sign_with_codesign(
                        tool="fake-codesign",
                        infile=str(infile),
                        outfile=str(root / "out.dmg"),
                        timestamp_url="",
                        options="",
                        entitlements="",
                        cert_path=str(cert),
                        password="secret",
                        identity="",
                    )

                cmd = recorded[0]
                for flag in expected:
                    self.assertIn(flag, cmd)
                for flag in forbidden:
                    self.assertNotIn(flag, cmd)

    def test_ca_file_is_embedded_by_the_signers_that_support_chains(self) -> None:
        # A self-signed certificate verifies only if the verifier already
        # trusts it; a real one needs its issuing chain carried in the
        # signature, which is what the CA file supplies.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = self._cert(root, "cert.pem", True)
            ca = root / "ca.pem"
            ca.write_text(_PEM_CERTIFICATE, encoding="utf-8")
            infile = root / "app.exe"
            infile.write_text("EXE\n", encoding="utf-8")

            recorded: list[list[str]] = []
            with mock.patch.object(
                sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)
            ):
                sign_tool.sign_with_osslsigncode(
                    tool="fake-osslsigncode",
                    infile=str(infile),
                    outfile=str(root / "out.exe"),
                    timestamp_url="",
                    name="",
                    url="",
                    cert_path=str(cert),
                    password="",
                    ca_path=str(ca),
                )
                sign_tool.sign_with_codesign(
                    tool="fake-codesign",
                    infile=str(infile),
                    outfile=str(root / "out.dmg"),
                    timestamp_url="",
                    options="",
                    entitlements="",
                    cert_path=str(cert),
                    password="",
                    identity="",
                    ca_path=str(ca),
                )

            authenticode, apple = recorded
            self.assertEqual(authenticode[authenticode.index("-ac") + 1], str(ca))
            # rcodesign takes the chain as a further PEM source: the first
            # certificate pairs with the key, the rest form the chain.
            pem_flags = [i for i, a in enumerate(apple) if a == "--pem-file"]
            self.assertEqual(len(pem_flags), 2)
            self.assertEqual(apple[pem_flags[0] + 1], str(cert))
            self.assertEqual(apple[pem_flags[1] + 1], str(ca))

    def test_cosign_reuses_a_key_it_already_owns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            key = root / "cosign.key"
            key.write_text(_COSIGN_PRIVATE_KEY, encoding="utf-8")

            recorded: list[list[str]] = []
            with mock.patch.object(
                sign_tool, "run_cmd", side_effect=lambda cmd, **kw: recorded.append(cmd)
            ):
                resolved = sign_tool.resolve_cosign_key(
                    tool="fake-cosign",
                    cert_path=str(key),
                    password="",
                    tmpdir=tmp,
                )

            self.assertEqual(resolved, str(key))
            self.assertEqual(recorded, [], "an existing cosign key must not be re-imported")

    def test_cosign_imports_a_pem_certificate(self) -> None:
        # One PEM can back all three signers, but only after cosign rewraps it
        # into its own key envelope.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = self._cert(root, "cert.pem", True)

            recorded: list[list[str]] = []

            def fake(cmd: list[str], **_kw: object) -> None:
                recorded.append(cmd)
                _fake_cosign(cmd)

            with mock.patch.object(sign_tool, "run_cmd", side_effect=fake):
                resolved = sign_tool.resolve_cosign_key(
                    tool="fake-cosign",
                    cert_path=str(cert),
                    password="pw",
                    tmpdir=tmp,
                )

            self.assertEqual(recorded[0][1], "import-key-pair")
            self.assertEqual(recorded[0][recorded[0].index("--key") + 1], str(cert))
            self.assertTrue(pathlib.Path(resolved).is_file())
            self.assertTrue(sign_tool.is_cosign_private_key(resolved))

    def test_cosign_converts_a_pkcs12_certificate_when_openssl_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = self._cert(root, "cert.p12", False)

            recorded: list[list[str]] = []

            def fake(cmd: list[str], **_kw: object) -> None:
                recorded.append(cmd)
                if pathlib.Path(cmd[0]).name == "fake-openssl":
                    pathlib.Path(cmd[cmd.index("-out") + 1]).write_text(
                        _PEM_CERTIFICATE, encoding="utf-8"
                    )
                    return
                _fake_cosign(cmd)

            with mock.patch.object(sign_tool, "run_cmd", side_effect=fake):
                resolved = sign_tool.resolve_cosign_key(
                    tool="fake-cosign",
                    cert_path=str(cert),
                    password="pw",
                    tmpdir=tmp,
                    openssl="fake-openssl",
                )

            convert, importer = recorded
            self.assertEqual(convert[1], "pkcs12")
            self.assertEqual(convert[convert.index("-in") + 1], str(cert))
            self.assertIn("-nodes", convert)
            # cosign reads the first PEM block, so certificates must be excluded.
            self.assertIn("-nocerts", convert)
            self.assertEqual(convert[convert.index("-passin") + 1], "env:RULES_SIGNING_P12_PASSWORD")

            # The imported key must come from the converted PEM, not the p12.
            self.assertEqual(importer[1], "import-key-pair")
            self.assertEqual(
                importer[importer.index("--key") + 1],
                convert[convert.index("-out") + 1],
            )
            self.assertTrue(sign_tool.is_cosign_private_key(resolved))

    def test_cosign_retries_pkcs12_conversion_with_the_legacy_provider(self) -> None:
        # PKCS#12 files written by older tools use ciphers OpenSSL 3 exposes
        # only through its legacy provider.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = self._cert(root, "cert.p12", False)

            recorded: list[list[str]] = []

            def fake(cmd: list[str], **_kw: object) -> None:
                recorded.append(cmd)
                if pathlib.Path(cmd[0]).name != "fake-openssl":
                    _fake_cosign(cmd)
                    return
                if "-legacy" not in cmd:
                    raise subprocess.CalledProcessError(1, cmd)
                pathlib.Path(cmd[cmd.index("-out") + 1]).write_text(
                    _PEM_CERTIFICATE, encoding="utf-8"
                )

            with mock.patch.object(sign_tool, "run_cmd", side_effect=fake):
                sign_tool.resolve_cosign_key(
                    tool="fake-cosign",
                    cert_path=str(cert),
                    password="pw",
                    tmpdir=tmp,
                    openssl="fake-openssl",
                )

            self.assertNotIn("-legacy", recorded[0])
            self.assertIn("-legacy", recorded[1])

    def test_cosign_pkcs12_without_openssl_explains_how_to_proceed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = self._cert(root, "cert.p12", False)

            with self.assertRaises(ValueError) as ctx:
                sign_tool.resolve_cosign_key(
                    tool="fake-cosign",
                    cert_path=str(cert),
                    password="pw",
                    tmpdir=tmp,
                )

            message = str(ctx.exception)
            self.assertIn("PKCS#12", message)
            self.assertIn("openssl toolchain", message)


if __name__ == "__main__":
    unittest.main()
