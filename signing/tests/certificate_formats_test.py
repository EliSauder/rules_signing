"""Verifies the `certificate_*` format conversion rules.

Each output is read back with openssl, and the strong-name files are decoded
by hand and compared with the source certificate's RSA modulus, since nothing
else on a build host can read an `.snk`.
"""

import argparse
import os
import subprocess
import sys
import tempfile
import unittest

from python.runfiles import Runfiles

_REPO = "rules_signing"
_ARGS = argparse.Namespace()
_RUNFILES = Runfiles.Create()


def _rlocation(rootpath: str) -> str:
    key = rootpath[len("../"):] if rootpath.startswith("../") else "{}/{}".format(_REPO, rootpath)
    resolved = _RUNFILES.Rlocation(key)
    if not resolved:
        raise AssertionError("no runfile for '{}'".format(rootpath))
    return resolved


def _read(rootpath: str, mode: str = "rb"):
    with open(_rlocation(rootpath), mode) as handle:
        return handle.read()


def _openssl(*args):
    result = subprocess.run(
        [_ARGS.openssl] + list(args), capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise AssertionError("openssl {} failed:\n{}".format(" ".join(args), result.stderr))
    return result.stdout


def _modulus(*args):
    return int(_openssl(*args).strip().split("=", 1)[1], 16)


class CertificateFormatsTest(unittest.TestCase):
    def test_pem_holds_key_and_certificate(self):
        text = _read(_ARGS.pem, "r")
        self.assertIn("PRIVATE KEY", text)
        self.assertIn("BEGIN CERTIFICATE", text)
        self.assertNotIn("ENCRYPTED", text)

    def test_p12_and_keystore_open_with_the_password_and_alias(self):
        for label, path in (("p12", _ARGS.p12), ("keystore", _ARGS.keystore)):
            with self.subTest(format=label):
                out = _openssl(
                    "pkcs12", "-in", _rlocation(path), "-passin",
                    "pass:" + _ARGS.password, "-nodes",
                )
                self.assertIn("friendlyName: converted", out)
                self.assertIn("PRIVATE KEY", out)
                self.assertIn("BEGIN CERTIFICATE", out)

    def test_keypair_works_with_cosign(self):
        key = _rlocation(_ARGS.private_key)
        self.assertIn("SIGSTORE PRIVATE KEY", _read(_ARGS.private_key, "r"))

        with tempfile.TemporaryDirectory() as tmp:
            blob = os.path.join(tmp, "blob.txt")
            bundle = os.path.join(tmp, "blob.bundle.json")
            config = os.path.join(tmp, "signing-config.json")
            with open(blob, "w", encoding="utf-8") as handle:
                handle.write("hello")
            env = dict(os.environ, COSIGN_PASSWORD=_ARGS.password)
            created = subprocess.run(
                [_ARGS.cosign, "signing-config", "create", "--out", config],
                capture_output=True, text=True, env=env, check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            sign = subprocess.run(
                [_ARGS.cosign, "sign-blob", "--key", key, "--yes",
                 "--signing-config", config, "--bundle", bundle, blob],
                capture_output=True, text=True, env=env, check=False,
            )
            self.assertEqual(sign.returncode, 0, sign.stderr)
            verify = subprocess.run(
                [_ARGS.cosign, "verify-blob", "--key", _rlocation(_ARGS.public_key),
                 "--bundle", bundle, "--insecure-ignore-tlog", blob],
                capture_output=True, text=True, env=env, check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_snk_matches_the_source_rsa_key(self):
        expected = _modulus("x509", "-in", _rlocation(_ARGS.source_certificate), "-noout", "-modulus")
        size = (expected.bit_length() + 7) // 8

        pair = _read(_ARGS.snk)
        self.assertEqual(pair[:12], bytes([0x07, 0x02, 0, 0, 0, 0x24, 0, 0]) + b"RSA2")
        self.assertEqual(int.from_bytes(pair[12:16], "little"), size * 8)
        n = int.from_bytes(pair[20:20 + size], "little")
        half = size // 2
        p = int.from_bytes(pair[20 + size:20 + size + half], "little")
        q = int.from_bytes(pair[20 + size + half:20 + size + 2 * half], "little")
        d = int.from_bytes(pair[-size:], "little")
        self.assertEqual(n, expected)
        self.assertEqual(p * q, n)
        self.assertEqual(pow(pow(7, 65537, n), d, n), 7)

        public = _read(_ARGS.public_snk)
        self.assertEqual(public[:8], bytes([0, 0x24, 0, 0, 4, 0x80, 0, 0]))
        self.assertEqual(int.from_bytes(public[8:12], "little"), len(public) - 12)
        self.assertEqual(public[20:24], b"RSA1")
        self.assertEqual(int.from_bytes(public[-size:], "little"), expected)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "openssl", "pem", "p12", "keystore", "snk", "public-snk",
        "source-certificate", "private-key", "public-key", "password", "cosign",
    ):
        parser.add_argument("--" + name, required=True)
    return parser.parse_known_args(argv)


if __name__ == "__main__":
    parsed, remaining = parse_args(sys.argv[1:])
    _ARGS.__dict__.update(vars(parsed))
    _ARGS.openssl = _rlocation(_ARGS.openssl)
    _ARGS.cosign = _rlocation(_ARGS.cosign)
    unittest.main(argv=[sys.argv[0]] + remaining)
