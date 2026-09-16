import argparse
import pathlib
import sys
import unittest
from typing import NamedTuple

from python.runfiles import runfiles


class OutputCase(NamedTuple):
    manifest_rootpath: str
    out_prefix: str
    src_root_rootpath: str


def _parse_outputs_case(raw: str) -> OutputCase:
    manifest_rootpath, out_prefix, src_root_rootpath = raw.split("::", 2)
    return OutputCase(manifest_rootpath, out_prefix, src_root_rootpath)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--outputs",
        dest="outputs",
        action="append",
        default=[],
        type=_parse_outputs_case,
        help=(
            "<output manifest rootpath>::<output directory prefix>::"
            "<source root rootpath>, repeatable. The manifest lists the "
            "target's declared outputs, which is what a `sign` target now "
            "consists of instead of one directory."
        ),
    )
    parser.add_argument(
        "--mixed-tree",
        dest="mixed_trees",
        action="append",
        default=[],
        help="Tree rootpath, repeatable.",
    )
    parser.add_argument(
        "src_file_rootpaths",
        nargs="*",
        help=(
            "Rootpaths to source files, expanded by Bazel from "
            "$(rootpaths :unsigned_files) / $(rootpaths :unsigned_text_files). "
            "The full source file list is recovered here rather than "
            "hardcoded, and matched to a --tree case by shared "
            "source-root prefix."
        ),
    )
    # unittest.main() also reads sys.argv, so anything this parser doesn't
    # recognize (e.g. -v) is left for it to consume below.
    args, remaining = parser.parse_known_args()
    sys.argv[1:] = remaining
    return args


_ARGS = _parse_args()
OUTPUT_CASES = _ARGS.outputs
MIXED_TREES = _ARGS.mixed_trees
SRC_FILE_ROOTPATHS = _ARGS.src_file_rootpaths

_RUNFILES = runfiles.Create()


def _rlocation(rootpath: str) -> pathlib.Path:
    path = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    assert path, f"missing runfile: {rootpath}"
    return pathlib.Path(path)


def _signed_tree_dir(tree_rootpath: str) -> pathlib.Path:
    """Resolves a declared directory output to its on-disk directory.

    A directory source is signed into a tree artifact, which is registered as
    one runfile whose Rlocation resolves directly to the physical bazel-out
    directory. That works the same way on Linux/macOS and on Windows's
    manifest-only runfiles, unlike assuming a path under TEST_SRCDIR is a
    real, walkable directory.
    """
    return _rlocation(tree_rootpath)


def _declared_outputs(case: OutputCase) -> "dict[str, str]":
    """Maps each declared output to its path relative to the output directory.

    A `sign` target's outputs are ordinary files, one per source (plus the
    sidecar files a detached signature consists of), rather than a single
    directory that has to be walked to find out what is in it. The manifest
    therefore *is* the output list, which is what makes it worth asserting
    against.
    """

    text = _rlocation(case.manifest_rootpath).read_text(encoding="utf-8")
    prefix = case.out_prefix + "/"
    outputs = {}
    for line in text.split("\n"):
        if not line:
            continue
        assert line.startswith(prefix), f"{line} is not under {prefix}"
        outputs[line] = line[len(prefix):]
    return outputs


def _collect_rel_files(root: pathlib.Path) -> set[str]:
    rels = set()
    for path in root.rglob("*"):
        if path.is_file():
            rels.add(path.relative_to(root).as_posix())
    return rels


def _src_files_under(src_root_rootpath: str) -> "list[str]":
    """Rootpaths from SRC_FILE_ROOTPATHS that live under src_root_rootpath."""
    prefix = src_root_rootpath + "/"
    return [p for p in SRC_FILE_ROOTPATHS if p.startswith(prefix)]


class SignIntegrationTest(unittest.TestCase):
    def test_all_sign_rule_parameter_permutations_build_and_preserve_layout(self) -> None:
        self.assertGreater(len(OUTPUT_CASES), 0, "missing output manifest args")
        self.assertGreater(len(SRC_FILE_ROOTPATHS), 0, "missing source file runfile args")

        for case in OUTPUT_CASES:
            src_rootpaths = _src_files_under(case.src_root_rootpath)
            self.assertGreater(
                len(src_rootpaths),
                0,
                f"no source files found under {case.src_root_rootpath}",
            )

            outputs = _declared_outputs(case)

            # Each source is signed into its own file, under the path it had
            # in the source. None of these fixtures has resolvable signing
            # material, so no detached signature is declared beside them and
            # the outputs are exactly the inputs.
            self.assertEqual(
                set(outputs.values()),
                set(src_rootpaths),
                f"declared outputs mismatch for {case.manifest_rootpath} "
                f"(input {case.src_root_rootpath})",
            )

            for output_rootpath, rel in outputs.items():
                path = _rlocation(output_rootpath)
                self.assertTrue(path.is_file(), f"expected an output file: {path}")
                self.assertEqual(
                    path.read_text(encoding="utf-8"),
                    _rlocation(rel).read_text(encoding="utf-8"),
                    f"content mismatch: {rel}",
                )

    def test_mixed_content_directory_is_flattened_and_fully_preserved(self) -> None:
        self.assertGreater(len(MIXED_TREES), 0, "missing mixed tree runfile args")

        expected = {
            "bin/app.exe": "fake pe payload",
            "bin/notes.txt": "notes next to a pe file",
            "bin/plugins/helper.dll": "fake dll payload",
            "docs/readme.txt": "readme payload",
            "config.yaml": "config payload",
            "mac/installer.dmg": "fake dmg payload",
        }

        for rel_tree in MIXED_TREES:
            tree = _signed_tree_dir(rel_tree)
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")

            # A lone directory input is flattened, so the layout is preserved
            # at the output root rather than nested under the input name.
            self.assertEqual(
                _collect_rel_files(tree),
                set(expected),
                f"mixed tree layout mismatch for {rel_tree}",
            )

            # Without resolvable signing material every file, regardless of the
            # tool that would sign it, must survive the recursion untouched.
            for rel_file, content in expected.items():
                self.assertEqual(
                    (tree / rel_file).read_text(encoding="utf-8"),
                    content,
                    f"mixed tree content mismatch: {rel_file}",
                )


if __name__ == "__main__":
    unittest.main()
