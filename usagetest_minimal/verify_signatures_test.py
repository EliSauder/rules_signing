"""Verify real signatures with only osslsigncode and cosign registered."""

import argparse
import pathlib
import subprocess
import unittest

from python.runfiles import Runfiles


class SignatureVerificationTest(unittest.TestCase):
    def resolve(self, path):
        resolved = RUNFILES.Rlocation(path)
        self.assertIsNotNone(resolved, f"missing runfile: {path}")
        self.assertTrue(pathlib.Path(resolved).is_file(), resolved)
        return resolved

    def verify(self, command, marker):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(marker, output)

    def test_authenticode_signatures(self):
        self.assertEqual(len(ARGS.script), 2)
        unsigned = pathlib.Path(self.resolve(ARGS.unsigned_script)).read_bytes()
        for artifact in ARGS.script:
            with self.subTest(artifact=artifact):
                signed = self.resolve(artifact)
                self.assertNotEqual(pathlib.Path(signed).read_bytes(), unsigned)
                self.verify(
                    [
                        self.resolve(ARGS.osslsigncode),
                        "verify",
                        "-CAfile",
                        self.resolve(ARGS.ca),
                        "-in",
                        signed,
                    ],
                    "Signature verification: ok",
                )

    def test_detached_signatures(self):
        self.assertEqual(len(ARGS.blob_outputs), 2)
        unsigned = pathlib.Path(self.resolve(ARGS.unsigned_blob)).read_bytes()
        for outputs in ARGS.blob_outputs:
            with self.subTest(outputs=outputs):
                files = {pathlib.Path(p).name: self.resolve(p) for p in outputs}
                self.assertEqual(len(outputs), 3)
                self.assertEqual(
                    set(files),
                    {"message.txt", "message.txt.sig", "message.txt.bundle.json"},
                )
                self.assertEqual(pathlib.Path(files["message.txt"]).read_bytes(), unsigned)
                self.assertTrue(pathlib.Path(files["message.txt.sig"]).read_bytes())
                self.verify(
                    [
                        self.resolve(ARGS.cosign),
                        "verify-blob",
                        "--key",
                        self.resolve(ARGS.public_key),
                        "--bundle",
                        files["message.txt.bundle.json"],
                        "--insecure-ignore-tlog",
                        files["message.txt"],
                    ],
                    "Verified OK",
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("osslsigncode", "cosign", "ca", "public-key", "unsigned-script", "unsigned-blob"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--script", action="append", required=True)
    parser.add_argument("--blob-outputs", nargs="+", action="append", required=True)
    ARGS, remaining = parser.parse_known_args()
    RUNFILES = Runfiles.Create()
    unittest.main(argv=[__file__] + remaining)
