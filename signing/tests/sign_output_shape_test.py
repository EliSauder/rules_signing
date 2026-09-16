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

    def assert_every_output_is_detached(self, case: str) -> None:
        """Asserts nothing in `case` was signed in place.

        Named outputs are deliberately not spelled out here. Which files a
        third-party binary rule reports varies by platform in ways that are
        that rule's business and not this project's contract -- `sh_binary`
        adds a `<name>.exe` stub on Windows beside the bare name it reports
        everywhere, `scala_binary` replaces the bare name with one -- and
        pinning those names tests the ruleset rather than the registry.

        What a `not_native()` row promises is exactly this invariant: every
        file the rule produces gets a detached signature, so none of them was
        routed to a native signer. A launcher stub that reached osslsigncode
        would appear here as a file with no sidecars, which is the bug these
        fixtures exist to catch.
        """

        outputs = _outputs(case)
        signed = [
            rel for rel in outputs
            if not any(rel.endswith(suffix) for suffix in _SIDECARS)
        ]
        self.assertTrue(signed, f"{case} declared no signed outputs")
        for rel in signed:
            for suffix in _SIDECARS:
                self.assertIn(
                    rel + suffix,
                    outputs,
                    f"{rel} has no {suffix}, so it was signed in place",
                )
        for rel, path in outputs.items():
            self.assertTrue(path.exists(), f"declared but not produced: {rel}")

    def assert_jvm_jar_is_embedded(self, case: str) -> None:
        """Asserts a JVM target's `.jar` is embedded-signed; nothing else is.

        A launcher's own name is not relied on here, for the same reason
        `assert_every_output_is_detached` does not: it varies by platform
        (`<name>.exe` on Windows, the bare name elsewhere for `scala_binary`,
        a `.jdeps` manifest for the Kotlin/Scala toolchains). `.jar` does not
        have that problem -- every JVM ruleset here names its jar output
        literally -- so matching by extension is exact rather than a guess.
        """

        outputs = _outputs(case)
        signed = [
            rel for rel in outputs
            if not any(rel.endswith(suffix) for suffix in _SIDECARS)
        ]
        self.assertTrue(signed, f"{case} declared no signed outputs")
        jars = [rel for rel in signed if rel.endswith(".jar")]
        self.assertTrue(jars, f"{case} declared no .jar output")
        for rel in signed:
            has_sidecars = all(rel + suffix in outputs for suffix in _SIDECARS)
            if rel.endswith(".jar"):
                self.assertFalse(
                    has_sidecars, f"{rel} has sidecars, so it was not embedded-signed"
                )
            else:
                self.assertTrue(
                    has_sidecars, f"{rel} has no sidecars, so it was signed in place"
                )
        for rel, path in outputs.items():
            self.assertTrue(path.exists(), f"declared but not produced: {rel}")


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

    def test_a_shell_script_is_not_natively_signed(self) -> None:
        """`sh_binary` is executable, and gets a detached signature anyway.

        A real rules_shell target, not a hypothesis: it is covered by a
        `not_native()` row, and this proves that decision holds against the
        rule it actually describes -- including the `<name>.exe` stub the
        rule adds on Windows, which is the output an extension check would
        otherwise hand to osslsigncode.
        """

        self.assert_every_output_is_detached("shell_greeting")

    def test_a_jvm_jar_is_natively_signed_but_its_jdeps_is_not(self) -> None:
        """`kt_jvm_binary`'s jar is embedded; its jdeps is not a jar.

        A real rules_kotlin target. The `.jar` is signed in place by
        `jarsigner`, but `.jdeps` is not a jar -- it is a dependency manifest
        the Kotlin toolchain writes beside it -- so it is left to cosign.
        """

        self.assert_jvm_jar_is_embedded("kotlin_greeting")

    def test_a_scala_jar_is_natively_signed_but_its_launcher_is_not(self) -> None:
        """As kotlin_greeting, for a real rules_scala target.

        `scala_binary` additionally emits a launcher script beside its jar --
        named `<name>.exe` on Windows, the bare name elsewhere -- and that
        launcher is not a jar either, so it too is left to cosign while the
        jar itself is signed in place by `jarsigner`. This is also the
        fixture that caught `scala_binary` missing from the registry: with no
        row to speak for it, that launcher fell through to being judged by
        name and was signed in place by osslsigncode on Windows.
        """

        self.assert_jvm_jar_is_embedded("scala_greeting")

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
