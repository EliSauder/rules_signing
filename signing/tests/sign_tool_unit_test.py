import pathlib
import shutil
import tempfile
import unittest
import json
from unittest import mock

from python.runfiles import runfiles

from signing.private.tools import sign_tool


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
        bundle = pathlib.Path(cmd[cmd.index("--bundle") + 1])
        bundle.write_text('{"signature":"detached"}\n', encoding="utf-8")
        return

    # rcodesign: `codesign sign [flags...] <input> <output>`.
    _append_marker(cmd[-2], cmd[-1], b"SIGNED:codesign\n")


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
            cert = root / "cert.p12"
            cert.write_text("cert", encoding="utf-8")

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

            # Direct file.
            resolved = sign_tool.resolve_cert_path(
                cert_file=str(cert_file),
                cert_template="",
                cert_encoding="path",
                stamps={},
                defaults={},
                tmpdir=tmp,
            )
            self.assertEqual(resolved, str(cert_file))

            # Template path.
            resolved = sign_tool.resolve_cert_path(
                cert_file="",
                cert_template="{CERT_PATH}",
                cert_encoding="path",
                stamps={},
                defaults={"CERT_PATH": str(cert_file)},
                tmpdir=tmp,
            )
            self.assertEqual(resolved, str(cert_file))

            # Template base64.
            resolved = sign_tool.resolve_cert_path(
                cert_file="",
                cert_template="{CERT_B64}",
                cert_encoding="base64",
                stamps={},
                defaults={"CERT_B64": "Y2VydC1iYXNlNjQ="},
                tmpdir=tmp,
            )
            self.assertIsNotNone(resolved)
            self.assertEqual(pathlib.Path(resolved).read_text(encoding="utf-8"), "cert-base64")

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
            cert = root / "cert.p12"

            in_exe.parent.mkdir(parents=True, exist_ok=True)
            in_dmg.parent.mkdir(parents=True, exist_ok=True)
            in_txt.parent.mkdir(parents=True, exist_ok=True)
            in_exe.write_text("EXE\n", encoding="utf-8")
            in_dmg.write_text("DMG\n", encoding="utf-8")
            in_txt.write_text("TXT\n", encoding="utf-8")
            cert.write_text("CERT\n", encoding="utf-8")

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
            cert.write_text("key", encoding="utf-8")
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
            cert = root / "cert.p12"
            cert.write_text("cert", encoding="utf-8")
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
            cert = root / "cert.p12"
            cert.write_text("cert", encoding="utf-8")
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
            cert.write_text("key", encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main()
