import os
import pathlib
import sys
import unittest

OUTPUT_CASES = [a for a in sys.argv[1:] if not a.startswith("--mixed-tree=")]
MIXED_TREES = [
    a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--mixed-tree=")
]
sys.argv = [sys.argv[0]]


def _runfile(rel: str) -> pathlib.Path:
    return pathlib.Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"] / rel


def _collect_rel_files(root: pathlib.Path) -> set[str]:
    rels = set()
    for path in root.rglob("*"):
        if path.is_file():
            rels.add(path.relative_to(root).as_posix())
    return rels


class SignIntegrationTest(unittest.TestCase):
    def test_all_sign_rule_parameter_permutations_build_and_preserve_layout(self) -> None:
        self.assertGreater(len(OUTPUT_CASES), 0, "missing signed tree runfile args")

        for case in OUTPUT_CASES:
            rel_tree, rel_input = case.split("::", 1)
            tree = _runfile(rel_tree)
            src_root = _runfile(rel_input)
            expected_src_rel = _collect_rel_files(src_root)
            expected = {
                (pathlib.Path(rel_input) / rel_file).as_posix()
                for rel_file in expected_src_rel
            }
            self.assertTrue(tree.is_dir(), f"expected output tree directory: {tree}")
            actual = _collect_rel_files(tree)
            self.assertEqual(
                actual,
                expected,
                f"output layout mismatch for {rel_tree} (input {rel_input})",
            )

            # With no resolvable real signing material in integration fixtures, outputs
            # must preserve content and structure exactly.
            for rel_file in expected_src_rel:
                expected_text = (src_root / rel_file).read_text(encoding="utf-8")
                output_rel = (pathlib.Path(rel_input) / rel_file).as_posix()
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
            tree = _runfile(rel_tree)
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
