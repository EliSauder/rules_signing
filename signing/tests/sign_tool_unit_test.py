import pathlib
import tempfile
import unittest
from unittest import mock

from signing.private.tools import sign_tool


def _fake_run_cmd(cmd: list[str]) -> None:
    tool = pathlib.Path(cmd[0]).name
    if tool == "security":
        return
    if "osslsigncode" in tool:
        in_path = cmd[cmd.index("-in") + 1]
        out_path = cmd[cmd.index("-out") + 1]
        data = pathlib.Path(in_path).read_text(encoding="utf-8")
        pathlib.Path(out_path).write_text(data + "SIGNED:osslsigncode\n", encoding="utf-8")
        return

    # codesign puts target path as the last argument.
    out_path = cmd[-1]
    data = pathlib.Path(out_path).read_text(encoding="utf-8")
    pathlib.Path(out_path).write_text(data + "SIGNED:codesign\n", encoding="utf-8")


class SignToolUnitTest(unittest.TestCase):
    def test_detect_tool(self) -> None:
        self.assertEqual(sign_tool.detect_tool("bin/App.EXE"), "osslsigncode")
        self.assertEqual(sign_tool.detect_tool("dist/image.dmg"), "codesign")
        self.assertEqual(sign_tool.detect_tool("notes/readme.txt"), "")

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

    def test_signing_outputs_are_modified_for_signable_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd):
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

            class Args:
                osslsigncode_tool = "fake-osslsigncode"
                codesign_tool = "fake-codesign"
                timestamp_url = "https://timestamp.example.invalid"
                name = "Example"
                url = "https://example.invalid"
                options = "runtime"
                entitlements = ""
                tool = "auto"

            args = Args()
            sign_tool.sign_one(
                sign_mode="tree",
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
                sign_mode="tree",
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
                sign_mode="tree",
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

    def test_codesign_uses_certificate_when_identity_not_provided(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            in_dmg = root / "in" / "mac" / "app.dmg"
            out_dmg = root / "out" / "mac" / "app.dmg"
            cert = root / "cert.p12"

            in_dmg.parent.mkdir(parents=True, exist_ok=True)
            in_dmg.write_text("DMG\n", encoding="utf-8")
            cert.write_text("CERT\n", encoding="utf-8")

            class Args:
                osslsigncode_tool = "fake-osslsigncode"
                codesign_tool = "fake-codesign"
                timestamp_url = "https://timestamp.example.invalid"
                name = ""
                url = ""
                options = "runtime"
                entitlements = ""
                tool = "auto"

            with (
                mock.patch.object(sign_tool, "run_cmd", side_effect=_fake_run_cmd),
                mock.patch.object(
                    sign_tool,
                    "run_cmd_capture",
                    return_value='  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID"\n',
                ),
                mock.patch.object(sign_tool.sys, "platform", "darwin"),
            ):
                sign_tool.sign_one(
                    sign_mode="tree",
                    tool_mode="auto",
                    relpath="mac/app.dmg",
                    infile=str(in_dmg),
                    outfile=str(out_dmg),
                    args=Args(),
                    cert_path=str(cert),
                    password="top-secret-password",
                    identity="",
                )

            self.assertIn("SIGNED:codesign", out_dmg.read_text(encoding="utf-8"))

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
