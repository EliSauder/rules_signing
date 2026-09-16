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


def _parse_single_file_case(raw: str) -> OutputCase:
    tree_rootpath, src_rootpath = raw.split("::", 1)
    return OutputCase(tree_rootpath, src_rootpath)


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
        "--mixed-tree-with-sibling",
        dest="mixed_trees_with_sibling",
        action="append",
        default=[],
        help="Tree rootpath, repeatable.",
    )
    parser.add_argument(
        "--single-file",
        dest="single_file_cases",
        action="append",
        default=[],
        type=_parse_single_file_case,
        help="<tree rootpath>::<source file rootpath>, repeatable.",
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
MIXED_TREES_WITH_SIBLING = _ARGS.mixed_trees_with_sibling
SINGLE_FILE_CASES = _ARGS.single_file_cases
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
    def test_all_sign_rule_parameter_permutations_flatten_plain_files(self) -> None:
        """Plain-file `src`s must land flat at the output root.

        None of these fixtures' sources are directory artifacts, so `sign`
        must drop every bit of package-relative directory structure (e.g.
        `signing/tests/testdata_sign/docs/nested/guide.txt`) and place each
        file at the output root under its own basename (`guide.txt`).
        Reproducing that structure instead is exactly the bug this test
        guards against: a `sign()` target whose source lives a few packages
        deep (as `//programs/bomloader:bomloader_windows_zip_signed` does in
        the consuming repo) would otherwise nest its real output several
        directories below the label folder that downstream tooling expects
        it flat in, and get silently skipped there.
        """
        self.assertGreater(len(OUTPUT_CASES), 0, "missing signed tree runfile args")
        self.assertGreater(len(SRC_FILE_ROOTPATHS), 0, "missing source file runfile args")

        for case in OUTPUT_CASES:
            tree = _signed_tree_dir(case.tree_rootpath)
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")

            # `unsigned_files` and `unsigned_text_files` overlap (the latter
            # is a subset glob of the former's docs/), so the same rootpath
            # can appear twice in SRC_FILE_ROOTPATHS; dedupe before treating
            # repeats as basename collisions.
            src_rootpaths = sorted(set(_src_files_under(case.src_root_rootpath)))
            self.assertGreater(
                len(src_rootpaths),
                0,
                f"no source files found under {case.src_root_rootpath}",
            )

            expected = {pathlib.PurePosixPath(p).name for p in src_rootpaths}
            self.assertEqual(
                len(expected),
                len(src_rootpaths),
                f"fixture basenames collide, test can't tell files apart: {src_rootpaths}",
            )

            actual = _collect_rel_files(tree)
            self.assertEqual(
                actual,
                expected,
                f"output layout mismatch for {case.tree_rootpath} (input {case.src_root_rootpath}); "
                "plain files must be flattened to the output root",
            )

            # With no resolvable real signing material in integration fixtures, outputs
            # must preserve content exactly.
            for src_rootpath in src_rootpaths:
                expected_text = _rlocation(src_rootpath).read_text(encoding="utf-8")
                basename = pathlib.PurePosixPath(src_rootpath).name
                actual_text = (tree / basename).read_text(encoding="utf-8")
                self.assertEqual(actual_text, expected_text, f"content mismatch: {basename}")

    def test_single_file_source_in_a_nested_package_is_flattened(self) -> None:
        """A lone, non-directory `src` must not carry its package path along.

        This is the exact shape of the originally reported bug: signing a
        single file whose `short_path` includes several package directories
        (e.g. `programs/bomloader/....zip`) must not reproduce those
        directories in the output tree.
        """
        self.assertGreater(len(SINGLE_FILE_CASES), 0, "missing single-file runfile args")

        for case in SINGLE_FILE_CASES:
            tree = _signed_tree_dir(case.tree_rootpath)
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")

            src_rootpath = case.src_root_rootpath
            basename = pathlib.PurePosixPath(src_rootpath).name

            actual = _collect_rel_files(tree)
            self.assertEqual(
                actual,
                {basename},
                f"single-file output for {case.tree_rootpath} kept its package path "
                f"instead of flattening to {basename!r}: found {actual}",
            )

            expected_text = _rlocation(src_rootpath).read_text(encoding="utf-8")
            actual_text = (tree / basename).read_text(encoding="utf-8")
            self.assertEqual(actual_text, expected_text, f"content mismatch: {basename}")

    def test_single_directory_source_is_flattened_to_tree_root(self) -> None:
        """A lone directory `src` is not wrapped in its own basename.

        `sign()` always produces a tree artifact, even for a single
        directory `src`. When that directory is the *only* source, wrapping
        it in a folder named after its own basename would just add an inert
        layer with nothing else in the tree to distinguish it from: the
        signed tree already *is* the signed version of that directory, so
        its contents are written directly at the tree's root, fully
        preserved.
        """
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

    def test_directory_source_keeps_its_own_name_and_structure_alongside_siblings(
        self,
    ) -> None:
        """A directory `src` nests under its own basename when not alone.

        Unlike the single-directory case above, a directory signed alongside
        another source cannot be flattened to the tree root -- it would
        collide with (or silently interleave into) its sibling. Instead it
        keeps its own basename (`mixed_tree`) as a top-level folder, with its
        full internal structure preserved beneath it, exactly like the
        single-directory case except for the added wrapping folder.
        """
        self.assertGreater(
            len(MIXED_TREES_WITH_SIBLING), 0, "missing mixed tree runfile args"
        )

        expected = {
            "mixed_tree/bin/app.exe": "fake pe payload",
            "mixed_tree/bin/notes.txt": "notes next to a pe file",
            "mixed_tree/bin/plugins/helper.dll": "fake dll payload",
            "mixed_tree/docs/readme.txt": "readme payload",
            "mixed_tree/config.yaml": "config payload",
            "mixed_tree/mac/installer.dmg": "fake dmg payload",
            "guide.txt": "unsigned nested text fixture\n",
        }

        for rel_tree in MIXED_TREES_WITH_SIBLING:
            tree = _signed_tree_dir(rel_tree)
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")

            self.assertEqual(
                _collect_rel_files(tree),
                set(expected),
                f"mixed tree with sibling layout mismatch for {rel_tree}",
            )

            for rel_file, content in expected.items():
                self.assertEqual(
                    (tree / rel_file).read_text(encoding="utf-8"),
                    content,
                    f"mixed tree with sibling content mismatch: {rel_file}",
                )


if __name__ == "__main__":
    unittest.main()
