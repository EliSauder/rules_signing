"""Verifies `certificate_snk` output with the strong-name tool `sn`.

`--sn=microsoft` uses sn.exe from the Windows SDK's .NET Framework tools;
`--sn=mono` uses Mono's sn from PATH. Both are run the same way:

* `sn -vf` accepts the assembly signed with the key pair, and rejects the
  delay-signed one (so the check is real).
* `sn -T` reports the token the .NET runtime reports for the signed assembly.
* `sn -t` reports that same token for the .public.snk.
* `sn -p` on the key pair writes exactly the .public.snk.
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from python.runfiles import Runfiles

_ARGS = argparse.Namespace()
_RUNFILES = Runfiles.Create()
_TOKEN = re.compile(r"public key token(?: is|:)\s*([0-9a-f]{16})", re.IGNORECASE)


def _resolve(rootpath):
    resolved = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    if not resolved:
        raise AssertionError("no runfile for '{}'".format(rootpath))
    return resolved


def _assembly(rootpath):
    # A csharp_binary's executable is a launcher next to its .dll.
    return _resolve(re.sub(r"\.(sh|bat)$", "", rootpath))


def _find_sn(flavor):
    if flavor == "mono":
        sn = shutil.which("sn")
        if not sn:
            raise AssertionError("Mono's `sn` is not on PATH (install mono-devel)")
        return sn
    roots = [
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
    ]
    found = []
    for root in roots:
        pattern = os.path.join(root, "Microsoft SDKs", "Windows", "*", "bin", "NETFX*Tools", "x64", "sn.exe")
        found.extend(glob.glob(pattern))
    if not found:
        raise AssertionError("sn.exe not found: install the Windows SDK's .NET Framework tools")
    return sorted(found)[-1]


class SnTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sn = _find_sn(_ARGS.sn)
        with open(_resolve(_ARGS.expected), "r") as handle:
            cls.expected_token = handle.read().split()[0].lower()

    def run_sn(self, *args):
        return subprocess.run(
            [self.sn, "-q"] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
        )

    def token(self, *args):
        result = self.run_sn(*args)
        self.assertEqual(result.returncode, 0, result.stdout)
        match = _TOKEN.search(result.stdout)
        self.assertIsNotNone(match, result.stdout)
        return match.group(1).lower()

    def test_signed_assembly_verifies(self):
        result = self.run_sn("-vf", _assembly(_ARGS.signed_assembly))
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_delay_signed_assembly_does_not_verify(self):
        result = self.run_sn("-vf", _assembly(_ARGS.delay_signed_assembly))
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_assembly_token_matches_runtime(self):
        self.assertEqual(self.token("-T", _assembly(_ARGS.signed_assembly)), self.expected_token)

    def test_public_snk_token_matches_runtime(self):
        self.assertEqual(self.token("-t", _resolve(_ARGS.public_snk)), self.expected_token)

    def test_sn_p_matches_public_snk(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "sn-p.snk")
            result = self.run_sn("-p", _resolve(_ARGS.key_pair), out)
            self.assertEqual(result.returncode, 0, result.stdout)
            with open(out, "rb") as handle:
                from_sn = handle.read()
        with open(_resolve(_ARGS.public_snk), "rb") as handle:
            self.assertEqual(handle.read().hex(), from_sn.hex())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sn", choices=("microsoft", "mono"), required=True)
    for name in ("signed-assembly", "delay-signed-assembly", "expected", "key-pair", "public-snk"):
        parser.add_argument("--" + name, required=True)
    parsed, remaining = parser.parse_known_args(sys.argv[1:])
    _ARGS.__dict__.update(vars(parsed))
    unittest.main(argv=[sys.argv[0]] + remaining)
