"""Verifies that signed outputs carry real, valid signatures.

The rest of the suite checks that `sign` lays out its outputs correctly, using
certificates that cannot be resolved so every file takes the passthrough path.
This test signs with the checked-in development certificates instead and hands
each artifact back to the tool that produced it, asserting both that the
signature validates and that the values passed through the rule -- description,
URL, identity, entitlements, hardened runtime -- are present in the signature.

Artifacts are named on the command line rather than discovered on disk so the
BUILD file stays the single description of what gets signed. Paths arrive as
rootpaths and are resolved through the runfiles library, which is required on
Windows where Bazel materializes runfiles as a manifest instead of a tree.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from python.runfiles import Runfiles

from signing.private.tools import sign_tool

_REPO = "rules_signing"

_ARGS = argparse.Namespace()
_RUNFILES = Runfiles.Create()


def _rlocation(rootpath: str) -> str:
    """Resolves a rootpath into a real filesystem path.

    Rootpaths pointing outside the main repository, such as the fetched signing
    tools, are expressed relative to the runfiles root as `../<repository>/...`,
    while paths within it are relative to the main repository's own directory.
    """

    if rootpath.startswith("../"):
        key = rootpath[len("../"):]
    else:
        key = "{}/{}".format(_REPO, rootpath)

    resolved = _RUNFILES.Rlocation(key)
    if not resolved:
        raise AssertionError("no runfile for '{}'".format(rootpath))
    return resolved


def _run(cmd, **kwargs):
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        **kwargs,
    )


class SignatureVerificationTest(unittest.TestCase):
    """Each case verifies a signature with the tool that created it."""

    def setUp(self):
        # The artifact lists come from the BUILD file, so an empty one would
        # turn a whole verification loop into a silent no-op.
        for group in ("pe", "macho", "signed_blob", "shared_blob"):
            self.assertTrue(
                getattr(_ARGS, group), "no artifacts passed for --{}".format(group)
            )

    def assertSucceeded(self, result, what):
        self.assertEqual(
            result.returncode,
            0,
            "{} failed ({}):\n{}\n{}".format(
                what, result.returncode, result.stdout, result.stderr
            ),
        )

    def test_pe_signatures_are_valid_and_carry_their_fields(self):
        for rootpath in _ARGS.pe:
            with self.subTest(artifact=rootpath):
                signed = _rlocation(rootpath)
                self.assertTrue(os.path.isfile(signed), signed)

                result = _run([
                    _ARGS.osslsigncode,
                    "verify",
                    "-CAfile",
                    _rlocation(_ARGS.generic_ca),
                    "-in",
                    signed,
                ])
                self.assertSucceeded(result, "osslsigncode verify")

                # osslsigncode reports per-signature status in its output and
                # still exits 0 for some failures, so the verdict is read from
                # the report rather than from the exit code alone.
                self.assertIn("Signature verification: ok", result.stdout)
                self.assertIn("Number of verified signatures: 1", result.stdout)

                # -n and -i, passed through from the rule's description and url.
                self.assertIn(
                    "Text description: {}".format(_ARGS.description), result.stdout
                )
                self.assertIn("URL description: {}".format(_ARGS.url), result.stdout)

    def test_macho_signatures_are_valid_and_carry_their_fields(self):
        for rootpath in _ARGS.macho:
            with self.subTest(artifact=rootpath):
                signed = _rlocation(rootpath)
                self.assertTrue(os.path.isfile(signed), signed)

                result = _run([_ARGS.codesign, "verify", signed])
                self.assertSucceeded(result, "rcodesign verify")
                self.assertIn("no problems detected", result.stdout + result.stderr)

                info = self.signature_info(signed)
                self.assertIn("identifier: {}".format(_ARGS.identity), info)

                # options = ["runtime"] must reach the code directory flags.
                self.assertIn("flags: CodeSignatureFlags(RUNTIME)", info)

                # The entitlements file must be embedded, not merely accepted.
                self.assertIn("entitlements_plist:", info)
                self.assertIn("com.apple.security.get-task-allow", info)

    def test_app_bundle_signature_is_valid(self):
        bundle = pathlib.Path(_rlocation(_ARGS.app_bundle))
        self.assertTrue(bundle.is_dir(), bundle)

        # Signing a bundle seals its contents into a code resources manifest,
        # which signing the executable alone would not produce.
        self.assertTrue((bundle / "Contents/_CodeSignature/CodeResources").is_file())

        executable = bundle / "Contents/MacOS/hello"
        self.assertTrue(executable.is_file(), executable)

        result = _run([_ARGS.codesign, "verify", str(executable)])
        self.assertSucceeded(result, "rcodesign verify")
        self.assertIn("no problems detected", result.stdout + result.stderr)

        info = self.signature_info(str(executable))

        # The bundle identifier comes from Info.plist, so a signed bundle is
        # distinguishable from a bare binary signed with the same certificate.
        self.assertIn("identifier: dev.rules-signing.hello", info)
        self.assertIn("flags: CodeSignatureFlags(RUNTIME)", info)

        # A zero digest here would mean the bundle metadata was never sealed.
        self.assertNotIn(
            "Resources (3): 0000000000000000000000000000000000000000"
            "000000000000000000000000",
            info,
        )

    def signature_info(self, path):
        result = _run([_ARGS.codesign, "print-signature-info", path])
        self.assertSucceeded(result, "rcodesign print-signature-info")
        return result.stdout

    def test_detached_blob_signatures_are_valid(self):
        for rootpath in _ARGS.signed_blob:
            with self.subTest(artifact=rootpath):
                signed = _rlocation(rootpath)
                self.assertTrue(os.path.isfile(signed), signed)

                bundle = signed + ".bundle.json"
                self.assertTrue(os.path.isfile(bundle), bundle)

                # The signature is also written beside the artifact; an empty
                # file would mean the bundle was produced but never read back.
                signature = pathlib.Path(signed + ".sig")
                self.assertTrue(signature.is_file(), signature)
                self.assertTrue(signature.read_text(encoding="utf-8").strip())

                self.assertVerifiedBlob(bundle, signed)

    def test_oci_image_signature_is_valid(self):
        layout = pathlib.Path(_rlocation(_ARGS.signed_oci))
        self.assertTrue((layout / "oci-layout").is_file(), layout)

        index = json.loads((layout / "index.json").read_text(encoding="utf-8"))
        algorithm, _, digest = index["manifests"][0]["digest"].partition(":")
        manifest = layout / "blobs" / algorithm / digest
        self.assertTrue(manifest.is_file(), manifest)

        # An OCI layout is signed by signing the manifest its index points at,
        # with the bundle stored inside the layout.
        bundle = layout / "signatures" / "{}.bundle.json".format(digest)
        self.assertTrue(bundle.is_file(), bundle)

        self.assertVerifiedBlob(str(bundle), str(manifest))

    def assertVerifiedBlob(self, bundle, artifact, public_key=None):
        result = _run([
            _ARGS.cosign,
            "verify-blob",
            "--key",
            _rlocation(public_key or _ARGS.cosign_public_key),
            "--bundle",
            bundle,
            # Signing is deliberately offline, so there is no transparency log
            # entry to check against.
            "--insecure-ignore-tlog",
            artifact,
        ])
        self.assertSucceeded(result, "cosign verify-blob")
        self.assertIn("Verified OK", result.stdout + result.stderr)

    def test_one_certificate_signs_for_every_tool(self):
        """A single certificate drives osslsigncode, rcodesign and cosign.

        The artifacts below were produced by three different signers from one
        `certificate` target, so this fails if any signer stops accepting the
        shared credential -- which is the whole point of issuing it as a plain
        code-signing certificate rather than a tool-specific one.
        """

        root = _rlocation(_ARGS.shared_root)

        pe = _rlocation(_ARGS.shared_pe)
        self.assertTrue(os.path.isfile(pe), pe)
        result = _run([_ARGS.osslsigncode, "verify", "-CAfile", root, "-in", pe])
        self.assertSucceeded(result, "osslsigncode verify")

        # The verifier trusts only the root, and the intermediate that closes
        # the gap to the leaf is not on disk here. Chaining to the root is
        # therefore only possible if `ca_file` embedded it in the signature.
        self.assertIn("Signature verification: ok", result.stdout)

        macho = _rlocation(_ARGS.shared_macho)
        self.assertTrue(os.path.isfile(macho), macho)
        result = _run([_ARGS.codesign, "verify", macho])
        self.assertSucceeded(result, "rcodesign verify")
        self.assertIn("no problems detected", result.stdout + result.stderr)

        # rcodesign carries the chain as additional certificates in the CMS
        # structure rather than in a dedicated field, so the intermediate that
        # `ca_file` supplied shows up alongside the leaf.
        info = self.signature_info(macho)
        self.assertIn("signature_verifies: true", info)
        self.assertIn(
            "subject: CN=rules_signing development intermediate CA (DO NOT TRUST)",
            info,
        )

        for rootpath in _ARGS.shared_blob:
            with self.subTest(artifact=rootpath):
                blob = _rlocation(rootpath)
                self.assertTrue(os.path.isfile(blob), blob)
                self.assertVerifiedBlob(
                    blob + ".bundle.json", blob, _ARGS.shared_public_key
                )

    def test_transparency_log_config_is_accepted_by_the_real_cosign(self):
        """Guards the unit tests' cosign stub against CLI drift.

        The signing config is built by invoking cosign, so the flags used to
        describe a Rekor service have to be the ones this cosign understands.
        Creating a config is purely local -- nothing is published here.
        """

        with tempfile.TemporaryDirectory() as tmp:
            offline = json.loads(
                pathlib.Path(
                    sign_tool.cosign_signing_config(_ARGS.cosign, tmp, "")
                ).read_text(encoding="utf-8")
            )
            self.assertNotIn("rekorTlogUrls", offline)

            public = json.loads(
                pathlib.Path(
                    sign_tool.cosign_signing_config(_ARGS.cosign, tmp, "default")
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                [service["url"] for service in public["rekorTlogUrls"]],
                ["https://rekor.sigstore.dev"],
            )

            private = json.loads(
                pathlib.Path(
                    sign_tool.cosign_signing_config(
                        _ARGS.cosign, tmp, "https://rekor.internal.example"
                    )
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                [service["url"] for service in private["rekorTlogUrls"]],
                ["https://rekor.internal.example"],
            )

    def test_signing_actually_changed_the_artifacts(self):
        """Guards against a passthrough copy being mistaken for a signature."""

        for rootpath in _ARGS.pe:
            with self.subTest(artifact=rootpath):
                data = pathlib.Path(_rlocation(rootpath)).read_bytes()

                # The Authenticode signature is appended as a PKCS#7 blob
                # carrying the SPC indirect data OID.
                self.assertIn(b"\x2b\x06\x01\x04\x01\x82\x37\x02\x01\x04", data)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osslsigncode", required=True)
    parser.add_argument("--cosign", required=True)
    parser.add_argument("--codesign", required=True)
    parser.add_argument("--generic-ca", required=True)
    parser.add_argument("--cosign-public-key", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--pe", action="append", default=[])
    parser.add_argument("--macho", action="append", default=[])
    parser.add_argument("--app-bundle", required=True)
    parser.add_argument("--signed-blob", action="append", default=[])
    parser.add_argument("--signed-oci", required=True)
    parser.add_argument("--shared-root", required=True)
    parser.add_argument("--shared-public-key", required=True)
    parser.add_argument("--shared-pe", required=True)
    parser.add_argument("--shared-macho", required=True)
    parser.add_argument("--shared-blob", action="append", default=[])
    return parser.parse_known_args(argv)


if __name__ == "__main__":
    parsed, remaining = parse_args(sys.argv[1:])
    _ARGS.__dict__.update(vars(parsed))

    # The tool paths are rootpaths too, and must be executable by absolute path.
    for tool in ("osslsigncode", "cosign", "codesign"):
        setattr(_ARGS, tool, _rlocation(getattr(_ARGS, tool)))

    sys.argv[1:] = remaining
    unittest.main()
