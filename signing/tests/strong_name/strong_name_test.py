"""Checks the .snk files from `certificate_snk` preserve strong-name identity.

Company A signs its release with the key pair, and everyone who trusts A
identifies A's assemblies by the public key token that comes out of that key:
allowlists, `InternalsVisibleTo`, binding policy and the GAC all key off it.

Three assemblies are compiled from the same source: the release (signed with
the key pair as its `keyfile`), and two builds that only have the public key
(`.public.snk`, delay-signed and public-signed), such as a developer or CI job
that must not hold A's private key. Each prints the token and public key it
ended up with. If the public key file is faithful, those builds are recognised
as company A's; if its token differs, a verifier that trusts A's token rejects
them.

The public key file must also be exactly what `sn -p` writes: the same
strong-name public key blob the compiler embeds in the signed release.

Finally, `friend_app` (signed with the key pair) uses internals that
`friend_lib` grants by the .public.snk key; the C# compiler only allows that
when both name the same key.
"""

import argparse
import sys
import unittest

from python.runfiles import Runfiles

_ARGS = argparse.Namespace()
_RUNFILES = Runfiles.Create()


def _resolve(rootpath):
    resolved = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    if not resolved:
        raise AssertionError("no runfile for '{}'".format(rootpath))
    return resolved


def _read_identity(rootpath):
    with open(_resolve(rootpath), "r") as handle:
        token, public_key = handle.read().split()
    return token, public_key


class StrongNameTrustTest(unittest.TestCase):
    def setUp(self):
        self.trusted_tokens = {_read_identity(_ARGS.signed)[0]}

    def assertTrusted(self, rootpath):
        token, _ = _read_identity(rootpath)
        self.assertIn(
            token,
            self.trusted_tokens,
            "an assembly built from the public key has token {} but company "
            "A's release has token {}: a verifier that trusts A's token "
            "would refuse it".format(token, ", ".join(self.trusted_tokens)),
        )

    def test_release_is_strong_named(self):
        token, public_key = _read_identity(_ARGS.signed)
        self.assertTrue(token)
        self.assertTrue(public_key)

    def test_public_snk_matches_sn_p_output(self):
        with open(_resolve(_ARGS.public_snk), "rb") as handle:
            public_snk = handle.read().hex().upper()
        _, release_public_key = _read_identity(_ARGS.signed)
        self.assertEqual(public_snk, release_public_key)

    def test_key_pair_is_a_signature_key(self):
        # Microsoft's `sn -p` copies the key pair's algorithm ID into the public
        # key (Mono's always writes CALG_RSA_SIGN), so it must be CALG_RSA_SIGN
        # as `sn -k` writes, or the extracted public key has another token.
        with open(_resolve(_ARGS.key_pair), "rb") as handle:
            header = handle.read(8)
        self.assertEqual(header[4:8], (0x2400).to_bytes(4, "little"))

    def test_friend_assembly_identity_is_accepted(self):
        with open(_resolve(_ARGS.friend), "r") as handle:
            self.assertEqual(handle.read().strip(), "friend access granted")

    def test_delay_signed_build_is_trusted_as_company_a(self):
        self.assertTrusted(_ARGS.delay_signed)

    def test_public_signed_build_is_trusted_as_company_a(self):
        self.assertTrusted(_ARGS.public_signed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("signed", "delay-signed", "public-signed", "friend", "public-snk", "key-pair"):
        parser.add_argument("--" + name, required=True)
    parsed, remaining = parser.parse_known_args(sys.argv[1:])
    _ARGS.__dict__.update(vars(parsed))
    unittest.main(argv=[sys.argv[0]] + remaining)
