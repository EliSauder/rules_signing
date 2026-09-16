"""Checks exactly which files a `sign` target produces.

This is the rule's contract: each source is signed into an output of its own
shape -- a file into a file, a directory into a directory -- and a source
signed with a detached signature is accompanied by the `.sig` and
`.bundle.json` files that signature consists of. Nothing else appears.

The check reads each target's declared outputs from a manifest rather than
listing a directory, because "which files were declared" is the question: a
signature that is written but never declared would not reach a consumer, and
a file that is declared but never written fails the build.
"""

import argparse
import pathlib
import sys
import unittest

from python.runfiles import runfiles

_SIDECARS = (".sig", ".bundle.json")


def _parse_case(raw: str) -> "tuple[str, tuple[str, str]]":
    name, manifest_rootpath, prefix = raw.split("::", 2)
    return name, (manifest_rootpath, prefix)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        dest="cases",
        action="append",
        default=[],
        type=_parse_case,
        help="<case name>::<output manifest rootpath>::<output directory>.",
    )
    args, remaining = parser.parse_known_args()
    sys.argv[1:] = remaining
    return args


_ARGS = _parse_args()
_CASES = dict(_ARGS.cases)
_RUNFILES = runfiles.Create()


def _rlocation(rootpath: str) -> pathlib.Path:
    path = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    assert path, f"missing runfile: {rootpath}"
    return pathlib.Path(path)


def _outputs(case: str) -> "dict[str, pathlib.Path]":
    """The case's declared outputs, keyed by their output-relative path."""

    manifest_rootpath, prefix = _CASES[case]
    text = _rlocation(manifest_rootpath).read_text(encoding="utf-8")
    outputs = {}
    for line in text.split("\n"):
        if not line:
            continue
        assert line.startswith(prefix + "/"), f"{line} is not under {prefix}"
        outputs[line[len(prefix) + 1:]] = _rlocation(line)
    return outputs


class SignOutputShapeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertGreater(len(_CASES), 0, "missing output manifest args")

    def assert_outputs(self, case: str, expected: "dict[str, tuple]") -> None:
        """Asserts `case` produced each source plus exactly the given sidecars."""

        want = set()
        for source, sidecars in expected.items():
            want.add(source)
            want.update(source + suffix for suffix in sidecars)

        outputs = _outputs(case)
        self.assertEqual(set(outputs), want, f"output set mismatch for {case}")
        for rel, path in outputs.items():
            self.assertTrue(path.exists(), f"declared but not produced: {rel}")

    def test_native_signature_replaces_the_file_and_adds_nothing(self) -> None:
        """A PE is signed in place, so the signed file is the whole output."""

        self.assert_outputs(
            "pe", {"signing/tests/hello.exe": ()}
        )

    def test_detached_signature_brings_its_sidecar_files(self) -> None:
        """cosign signs a blob detached, so the signature is its own files."""

        self.assert_outputs(
            "blobs",
            {
                "signing/tests/testdata_sign/docs/readme.txt": _SIDECARS,
                "signing/tests/testdata_sign/docs/nested/guide.txt": _SIDECARS,
            },
        )

    def test_extensionless_sources_are_shaped_like_any_other(self) -> None:
        """A name with no extension is not a special case of the output set.

        Which signer runs on this file is only settled when its header is
        read, at execution time, and it turns out to be a PE. That cannot
        change what the target produces, so the file is shaped by the same
        rule as a `.md` or a `.txt`: cosign's, because nothing in the name
        says otherwise. The PE signature is applied to the file as well.
        """

        self.assert_outputs("detected", {"signing/tests/hello_pe": _SIDECARS})

    def test_without_signing_material_only_the_sources_come_back(self) -> None:
        """No certificate means no signature, and so no files to declare."""

        self.assert_outputs(
            "unsigned",
            {
                "signing/tests/testdata_sign/bin/app.exe": (),
                "signing/tests/testdata_sign/bin/plugins/helper.dll": (),
                "signing/tests/testdata_sign/docs/readme.txt": (),
                "signing/tests/testdata_sign/docs/nested/guide.txt": (),
            },
        )

    def test_a_directory_source_stays_one_directory(self) -> None:
        """Its contents are the action's to decide, so it is a tree artifact."""

        outputs = _outputs("tree")
        self.assertEqual(len(outputs), 1, f"expected one output: {outputs}")
        (path,) = outputs.values()
        self.assertTrue(path.is_dir(), f"expected a directory output: {path}")

        # The detached signatures live inside it, where they did not have to
        # be declared one by one.
        names = {p.name for p in path.rglob("*")}
        self.assertIn("readme.txt", names)
        self.assertIn("readme.txt.sig", names)
        self.assertIn("readme.txt.bundle.json", names)


if __name__ == "__main__":
    unittest.main()
