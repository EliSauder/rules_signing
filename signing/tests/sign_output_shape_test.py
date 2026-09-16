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

    def test_an_extensionless_binary_is_recognised_without_its_name(self) -> None:
        """Nothing in this file's name says it is a PE. It is signed as one.

        The name is not what was consulted: the rule that builds this file
        reported it as a Windows binary while the build graph was being
        built, so it was routed to osslsigncode there. The signature is
        embedded, which is why the file is the entire output -- no `.sig`
        accompanies it, and nothing had to be read at execution time to
        establish that.
        """

        self.assert_outputs("detected", {"signing/tests/hello_pe": ()})

    def test_detection_reaches_one_file_in_a_group_and_not_its_neighbour(
        self,
    ) -> None:
        """Two files, one filegroup, two different answers.

        Detection is per file, not per target. The binary is classified from
        the rule that builds it and signed in place; the text file beside it
        is left to cosign and gains sidecars. A grouping rule is where a
        whole-target answer would be visibly wrong -- the group itself builds
        nothing, so the only correct verdict is the one each file brought
        with it.
        """

        self.assert_outputs(
            "mixed_group",
            {
                "signing/tests/hello_pe": (),
                "signing/tests/testdata_sign/docs/nested/guide.txt": _SIDECARS,
            },
        )

    def test_a_name_a_rule_invented_does_not_decide_the_signer(self) -> None:
        """An ELF called `.exe` is not signed as a Windows PE.

        `native_binary` names its output `<name>.exe` on every platform, so
        the extension here is its author's convention and not a fact about
        the bytes. The rule that built the binary targeted Linux, which has
        no native signature format, and that verdict stands rather than being
        overruled by the name -- so the file gets a detached signature and
        osslsigncode is never reached.
        """

        self.assert_outputs(
            "elf_named_exe",
            {"signing/tests/elf_named_exe.exe": _SIDECARS},
        )

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

    def test_always_gives_every_source_the_same_shape(self) -> None:
        """`detached_signatures = "always"` makes the name stop mattering.

        A `.exe` and a `.txt` are routed to different signers and would
        otherwise produce different output sets. Asking for a detached
        signature on everything is what makes the two identical, which is the
        point of the mode: a consumer can then predict a target's outputs from
        its sources alone.
        """

        self.assert_outputs(
            "always",
            {
                "signing/tests/hello.exe": _SIDECARS,
                "signing/tests/testdata_sign/docs/readme.txt": _SIDECARS,
            },
        )

    def test_never_leaves_only_what_a_signer_embeds(self) -> None:
        """The opposite end, and also uniform: sources and nothing else.

        The `.exe` still carries its embedded signature; the `.txt`, which no
        native signer claims, is simply copied.
        """

        self.assert_outputs(
            "never",
            {
                "signing/tests/hello.exe": (),
                "signing/tests/testdata_sign/docs/readme.txt": (),
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
