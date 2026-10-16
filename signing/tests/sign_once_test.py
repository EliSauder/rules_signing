"""A file that already carries a signature is not signed again.

Each pair is an artifact signed with one certificate and the result of
signing it again with another. The second signature would replace the first,
so the only correct output is the input, byte for byte.
"""

import pathlib
import sys
import unittest

from python.runfiles import runfiles

_RUNFILES = runfiles.Create()
_PATHS = sys.argv[1:]
del sys.argv[1:]


def _read(rootpath: str) -> bytes:
    path = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    assert path, f"missing runfile: {rootpath}"
    return pathlib.Path(path).read_bytes()


class SignOnceTest(unittest.TestCase):
    def test_an_existing_signature_is_kept(self) -> None:
        self.assertTrue(_PATHS and len(_PATHS) % 2 == 0, _PATHS)
        for original, resigned in zip(_PATHS[::2], _PATHS[1::2]):
            with self.subTest(artifact=original):
                self.assertEqual(_read(original), _read(resigned))


if __name__ == "__main__":
    unittest.main()
