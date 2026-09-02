import argparse
import pathlib
import sys
import unittest
from typing import NamedTuple

from python.runfiles import runfiles


class OutputCase(NamedTuple):
    tree_rootpath: str
    src_root_rootpath: str


def _parse_tree_case(raw: str) -> OutputCase:
    tree_rootpath, src_root_rootpath = raw.split("::", 1)
    return OutputCase(tree_rootpath, src_root_rootpath)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tree",
        dest="trees",
        action="append",
        default=[],
        type=_parse_tree_case,
        help="<tree rootpath>::<source root rootpath>, repeatable.",
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
OUTPUT_CASES = _ARGS.trees
MIXED_TREES = _ARGS.mixed_trees
SRC_FILE_ROOTPATHS = _ARGS.src_file_rootpaths

_RUNFILES = runfiles.Create()


def _rlocation(rootpath: str) -> pathlib.Path:
    path = _RUNFILES.Rlocation("rules_signing/" + rootpath)
    assert path, f"missing runfile: {rootpath}"
    return pathlib.Path(path)


def _signed_tree_dir(tree_rootpath: str) -> pathlib.Path:
    """Resolves a `sign()` tree-artifact output to its on-disk directory.

    A `sign()` output is a single declared directory, so it is registered as
    one runfile whose Rlocation resolves directly to the physical bazel-out
    directory. That works the same way on Linux/macOS and on Windows's
    manifest-only runfiles, unlike assuming a path under TEST_SRCDIR is a
    real, walkable directory.
    """
    return _rlocation(tree_rootpath)


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
        self.assertGreater(len(OUTPUT_CASES), 0, "missing signed tree runfile args")
        self.assertGreater(len(SRC_FILE_ROOTPATHS), 0, "missing source file runfile args")

        for case in OUTPUT_CASES:
            tree = _signed_tree_dir(case.tree_rootpath)
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")

            src_rootpaths = _src_files_under(case.src_root_rootpath)
            self.assertGreater(
                len(src_rootpaths),
                0,
                f"no source files found under {case.src_root_rootpath}",
            )

            src_root_prefix = case.src_root_rootpath + "/"
            expected = {
                (pathlib.Path(case.src_root_rootpath) / p[len(src_root_prefix):]).as_posix()
                for p in src_rootpaths
            }
            actual = _collect_rel_files(tree)
            self.assertEqual(
                actual,
                expected,
                f"output layout mismatch for {case.tree_rootpath} (input {case.src_root_rootpath})",
            )

            # With no resolvable real signing material in integration fixtures, outputs
            # must preserve content and structure exactly.
            for src_rootpath in src_rootpaths:
                rel_file = src_rootpath[len(src_root_prefix):]
                expected_text = _rlocation(src_rootpath).read_text(encoding="utf-8")
                output_rel = (pathlib.Path(case.src_root_rootpath) / rel_file).as_posix()
                actual_text = (tree / output_rel).read_text(encoding="utf-8")
                self.assertEqual(actual_text, expected_text, f"content mismatch: {rel_file}")

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
