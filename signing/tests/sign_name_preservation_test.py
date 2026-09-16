"""Checks that `sign` reproduces every input file name exactly.

The rule builds each output path by string manipulation on the input's
`short_path`, so a file name is easy to mangle by accident: normalizing case,
dropping a suffix after a dot, or losing everything after a space. Any of those
silently break whatever consumes the signed tree, and none of them would be
caught by a test that only counts files.

Expected names arrive in a manifest file rather than through `args` because
Bazel shell-tokenizes `args`, which would split the names containing spaces.

Names are compared in the canonical form produced by `_canonical` so that the
comparison stays about the rule rather than about the encoding a given Bazel
version happens to hand the name back in; see that function for details.
"""

import argparse
import os
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
        "--passthrough-outputs",
        required=True,
        help="Rootpath of the declared-output manifest of the unsigned copy.",
    )
    parser.add_argument(
        "--passthrough-prefix",
        required=True,
        help="Output directory those outputs are listed under.",
    )
    parser.add_argument(
        "--signed-outputs",
        required=True,
        help="Rootpath of the declared-output manifest of the signed copy.",
    )
    parser.add_argument(
        "--signed-prefix",
        required=True,
        help="Output directory those outputs are listed under.",
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


def _canonical(name: str) -> str:
    """Returns `name` with a mis-decoded UTF-8 name decoded back.

    Bazel keeps paths as raw bytes reinterpreted as Latin-1 characters. Under
    Bazel 8 on Linux and Windows those bytes come back from an output tree
    encoded to UTF-8 a second time, so a file named `café.txt` is listed as
    `cafÃ©.txt` although nothing renamed it (Bazel 9, and Bazel 8 on macOS, do
    not do this). File *contents* always keep the original bytes, so the
    manifest and the directory listing can disagree about the encoding of a
    name that is in fact identical.

    Undoing that double encoding, plus restoring any bytes the filesystem
    could not decode (they arrive as surrogates), puts both sides of the
    comparison in one form. It cannot mask a rule that really does rename a
    file: this only reinterprets the bytes of a name, it never changes which
    bytes are there, and every ASCII name -- which is all of the fixtures
    exercising case, spaces and suffixes -- is left exactly as it is.
    """

    try:
        name = os.fsencode(name).decode("utf-8")
    except (UnicodeError, ValueError):
        return name
    try:
        return name.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return name


def _expected_names() -> "list[str]":
    text = _rlocation(_ARGS.names_manifest).read_text(encoding="utf-8")
    return [_canonical(line) for line in text.split("\n") if line]


def _rel_files(manifest_rootpath: str, prefix: str) -> "dict[str, pathlib.Path]":
    """Maps each declared output from its canonical name to its real path.

    `sign` declares one output per source rather than a directory to be
    walked, so the names it produced are read from the manifest of those
    outputs. That is a stricter check than listing a directory: a name that
    never reached the output set is missing here rather than merely absent
    from disk.
    """

    text = _rlocation(manifest_rootpath).read_text(encoding="utf-8")
    rels = {}
    for line in text.split("\n"):
        if not line:
            continue
        assert line.startswith(prefix + "/"), f"{line} is not under {prefix}"
        rels[_canonical(line[len(prefix) + 1:])] = _rlocation(line)
    return rels


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
        self.assertTrue(
            any(not name.isascii() for name in self.expected),
            "no fixture exercises a non-ASCII name",
        )

    def test_canonicalization_only_undoes_double_encoding(self) -> None:
        """`_canonical` must not be able to paper over a real rename."""
        for name in self.expected:
            self.assertEqual(
                _canonical(name), name, "manifest is not canonical"
            )
        for name in self.expected:
            doubled = name.encode("utf-8").decode("latin-1")
            self.assertEqual(_canonical(doubled), name)

    def test_passthrough_copies_reproduce_every_name_exactly(self) -> None:
        self.assertEqual(
            set(_rel_files(_ARGS.passthrough_outputs, _ARGS.passthrough_prefix)),
            set(self.expected),
            "passthrough output names differ from the input names",
        )

    def test_real_signing_reproduces_every_name_exactly(self) -> None:
        actual = _rel_files(_ARGS.signed_outputs, _ARGS.signed_prefix)
        passthrough = _rel_files(
            _ARGS.passthrough_outputs, _ARGS.passthrough_prefix
        )

        # cosign signs detached, so each input keeps its own name and gains
        # siblings; the signed artifact itself must still be byte-identical.
        for name in self.expected:
            self.assertIn(name, actual, f"{name} is missing or was renamed")
            self.assertIn(
                name, passthrough, f"{name} is missing from the unsigned copy"
            )
            self.assertEqual(
                actual[name].read_bytes(),
                passthrough[name].read_bytes(),
                f"content changed while signing {name}",
            )
            self.assertIn(name + ".sig", actual, f"no signature beside {name}")

        # Nothing may appear that is not an input or one of its signatures.
        allowed = set(self.expected)
        for name in self.expected:
            allowed.update({name + ".sig", name + ".bundle.json"})
        self.assertEqual(
            set(actual) - allowed,
            set(),
            "signing produced unexpected (possibly renamed) files",
        )


if __name__ == "__main__":
    unittest.main()
