"""Checks that `sign` reproduces every input file name exactly.

The rule builds each output path by string manipulation on the input's
`short_path`, so a file name is easy to mangle by accident: normalizing case,
dropping a suffix after a dot, or losing everything after a space. Any of those
silently break whatever consumes the signed tree, and none of them would be
caught by a test that only counts files.

Expected names arrive in a manifest file rather than through `args` because
Bazel shell-tokenizes `args`, which would split the names containing spaces.
"""

import argparse
import pathlib
import sys
import unittest

from python.runfiles import runfiles


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--names-manifest",
        required=True,
        help="Rootpath of the file listing the expected source short_paths.",
    )
    parser.add_argument(
        "--passthrough-tree",
        required=True,
        help="Rootpath of the signed tree produced without a certificate.",
    )
    parser.add_argument(
        "--signed-tree",
        required=True,
        help="Rootpath of the signed tree produced by a real signer.",
    )
    # unittest.main() also reads sys.argv, so leave it anything we don't take.
    args, remaining = parser.parse_known_args()
    sys.argv[1:] = remaining
    return args


_ARGS = _parse_args()
_RUNFILES = runfiles.Create()


def _rlocation(rootpath: str) -> pathlib.Path:
    path = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    assert path, f"missing runfile: {rootpath}"
    return pathlib.Path(path)


def _expected_names() -> "list[str]":
    text = _rlocation(_ARGS.names_manifest).read_text(encoding="utf-8")
    return [line for line in text.split("\n") if line]


def _rel_files(root: pathlib.Path) -> "set[str]":
    return {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    }


class SignNamePreservationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = _expected_names()
        # Guards against the manifest silently going empty, which would make
        # every assertion below vacuously true.
        self.assertGreater(len(self.expected), 10, "manifest looks empty")

    def test_names_are_worth_testing(self) -> None:
        """The fixtures only prove anything if they are actually awkward."""
        joined = "".join(self.expected)
        for char in " '&$#;()[]{}%+=,!`~@":
            self.assertIn(char, joined, f"no fixture exercises {char!r}")

    def test_passthrough_copies_reproduce_every_name_exactly(self) -> None:
        tree = _rlocation(_ARGS.passthrough_tree)
        self.assertTrue(tree.is_dir(), f"expected a tree artifact: {tree}")

        self.assertEqual(
            _rel_files(tree),
            set(self.expected),
            "passthrough output names differ from the input names",
        )

    def test_real_signing_reproduces_every_name_exactly(self) -> None:
        passthrough_tree = _rlocation(_ARGS.passthrough_tree)
        self.assertTrue(
            passthrough_tree.is_dir(),
            f"expected a tree artifact: {passthrough_tree}",
        )
        tree = _rlocation(_ARGS.signed_tree)
        self.assertTrue(tree.is_dir(), f"expected a tree artifact: {tree}")

        actual = _rel_files(tree)

        # cosign signs detached, so each input keeps its own name and gains
        # siblings; the signed artifact itself must still be byte-identical.
        for name in self.expected:
            self.assertIn(name, actual, f"{name} is missing or was renamed")
            self.assertEqual(
                (tree / name).read_bytes(),
                (passthrough_tree / name).read_bytes(),
                f"content changed while signing {name}",
            )
            self.assertIn(name + ".sig", actual, f"no signature beside {name}")

        # Nothing may appear that is not an input or one of its signatures.
        allowed = set(self.expected)
        for name in self.expected:
            allowed.update({name + ".sig", name + ".bundle.json"})
        self.assertEqual(
            actual - allowed,
            set(),
            "signing produced unexpected (possibly renamed) files",
        )


if __name__ == "__main__":
    unittest.main()
