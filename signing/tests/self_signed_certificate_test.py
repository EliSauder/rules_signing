"""Verifies certificates issued by `self_signed_certificate` are real credentials.

Checking that the rule produced three files would prove very little: the point
of generating a certificate during the build is that artifacts signed with it
verify against it. So each case here hands the generated material back to the
tool that consumed it -- osslsigncode with the generated certificate as the
sole trust anchor, cosign with the generated public key -- and only then
inspects the certificate itself for the properties the rule promises (a
self-signed code-signing certificate carrying the configured subject and
lifetime).

Paths arrive as rootpaths and are resolved through the runfiles library, which
is required on Windows where Bazel materializes runfiles as a manifest rather
than a tree.
"""

import argparse
import datetime
import os
import re
import subprocess
import sys
import unittest

from python.runfiles import Runfiles

_REPO = "rules_signing"

_ARGS = argparse.Namespace()
_RUNFILES = Runfiles.Create()


def _rlocation(rootpath: str) -> str:
    if rootpath.startswith("../"):
        key = rootpath[len("../"):]
    else:
        key = "{}/{}".format(_REPO, rootpath)

    resolved = _RUNFILES.Rlocation(key)
    if not resolved:
        raise AssertionError("no runfile for '{}'".format(rootpath))
    return resolved


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kwargs)


class SelfSignedCertificateTest(unittest.TestCase):
    def assertSucceeded(self, result, what):
        self.assertEqual(
            result.returncode,
            0,
            "{} failed ({}):\n{}\n{}".format(
                what, result.returncode, result.stdout, result.stderr
            ),
        )

    def openssl_x509(self, certificate, *flags):
        result = _run([_ARGS.openssl, "x509", "-in", certificate, "-noout"] + list(flags))
        self.assertSucceeded(result, "openssl x509 {}".format(" ".join(flags)))
        return result.stdout

    def test_certificate_is_self_signed_with_the_configured_subject(self):
        for label, rootpath in (
            ("pem", _ARGS.pem_certificate),
            ("p12", _ARGS.p12_certificate),
        ):
            with self.subTest(certificate=label):
                certificate = _rlocation(rootpath)
                text = self.openssl_x509(certificate, "-subject", "-issuer", "-enddate")

                subject = re.search(r"^subject=(.*)$", text, re.MULTILINE).group(1)
                issuer = re.search(r"^issuer=(.*)$", text, re.MULTILINE).group(1)

                # openssl spells DN entries as either `CN=x` or `CN = x`
                # depending on its version, so the separator is normalised
                # away rather than pinned to one release's output.
                self.assertIn(
                    "CN={}".format(_ARGS.common_name),
                    subject.replace(" = ", "="),
                )

                # Self-signed means exactly this: the certificate is its own
                # issuer, which is why it needs no chain to verify against.
                self.assertEqual(subject, issuer)

                not_after = re.search(r"^notAfter=(.*)$", text, re.MULTILINE).group(1)
                expiry = datetime.datetime.strptime(
                    not_after.replace(" GMT", ""), "%b %d %H:%M:%S %Y"
                ).replace(tzinfo=datetime.timezone.utc)
                remaining = expiry - datetime.datetime.now(datetime.timezone.utc)

                # `validity_days` is counted from when the action ran, so the
                # remaining life is bounded by it rather than equal to it.
                self.assertGreater(remaining.days, _ARGS.validity_days - 2)
                self.assertLessEqual(remaining.days, _ARGS.validity_days)

    def test_certificate_is_usable_for_code_signing(self):
        for label, rootpath in (
            ("pem", _ARGS.pem_certificate),
            ("p12", _ARGS.p12_certificate),
        ):
            with self.subTest(certificate=label):
                text = self.openssl_x509(
                    _rlocation(rootpath),
                    "-ext",
                    "basicConstraints,keyUsage,extendedKeyUsage",
                )
                self.assertIn("Code Signing", text)
                self.assertIn("Digital Signature", text)

                # A leaf that claims to be a CA is rejected outright by some
                # verifiers, so the constraint is asserted rather than assumed.
                self.assertIn("CA:FALSE", text)

    def test_pem_material_carries_both_halves_of_the_credential(self):
        # osslsigncode is handed this one file as both `-certs` and `-key`, so
        # a PEM missing either block would fail only at signing time.
        with open(_rlocation(_ARGS.pem_material), "rb") as handle:
            material = handle.read()
        self.assertIn(b"PRIVATE KEY-----", material)
        self.assertIn(b"BEGIN CERTIFICATE-----", material)

    def test_p12_material_is_unlocked_by_the_configured_password(self):
        result = _run([
            _ARGS.openssl,
            "pkcs12",
            "-in",
            _rlocation(_ARGS.p12_material),
            "-passin",
            "pass:{}".format(_ARGS.p12_password),
            "-nokeys",
            "-noout",
        ])
        self.assertSucceeded(result, "openssl pkcs12")

    def test_signed_pe_verifies_against_the_generated_certificate(self):
        self.assertTrue(_ARGS.signed_pe, "no artifacts passed for --signed-pe")
        for pair in _ARGS.signed_pe:
            artifact, _, anchor = pair.partition("::")
            with self.subTest(artifact=artifact):
                signed = _rlocation(artifact)
                self.assertTrue(os.path.isfile(signed), signed)

                result = _run([
                    _ARGS.osslsigncode,
                    "verify",
                    "-CAfile",
                    _rlocation(anchor),
                    "-in",
                    signed,
                ])
                self.assertSucceeded(result, "osslsigncode verify")
                self.assertIn("Signature verification: ok", result.stdout)

    def test_signed_blob_verifies_against_the_generated_public_key(self):
        self.assertTrue(_ARGS.signed_blob, "no artifacts passed for --signed-blob")
        public_key = _rlocation(_ARGS.pem_public_key)
        for rootpath in _ARGS.signed_blob:
            with self.subTest(artifact=rootpath):
                artifact = _rlocation(rootpath)

                # cosign ignores X.509 and trusts the bare key, so a signature
                # made through the generated certificate has to verify against
                # the public key that certificate carries. That it does is what
                # proves `sign` imported this very key rather than inventing one.
                result = _run(
                    [
                        _ARGS.cosign,
                        "verify-blob",
                        "--key",
                        public_key,
                        "--bundle",
                        artifact + ".bundle.json",
                        "--insecure-ignore-tlog",
                        artifact,
                    ],
                    env=dict(os.environ, COSIGN_PASSWORD=""),
                )
                self.assertSucceeded(result, "cosign verify-blob")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--osslsigncode", required=True)
    parser.add_argument("--cosign", required=True)
    parser.add_argument("--common-name", required=True)
    parser.add_argument("--validity-days", type=int, required=True)
    parser.add_argument("--p12-password", required=True)
    parser.add_argument("--pem-material", required=True)
    parser.add_argument("--pem-certificate", required=True)
    parser.add_argument("--pem-public-key", required=True)
    parser.add_argument("--p12-material", required=True)
    parser.add_argument("--p12-certificate", required=True)
    parser.add_argument("--signed-pe", action="append", default=[])
    parser.add_argument("--signed-blob", action="append", default=[])
    return parser.parse_known_args(argv)


if __name__ == "__main__":
    parsed, remaining = parse_args(sys.argv[1:])
    _ARGS.__dict__.update(vars(parsed))

    # The tool paths are rootpaths too, and must be executable by absolute path.
    for tool in ("openssl", "osslsigncode", "cosign"):
        setattr(_ARGS, tool, _rlocation(getattr(_ARGS, tool)))

    unittest.main(argv=[sys.argv[0]] + remaining)
