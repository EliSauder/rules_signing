"""Verifies that `sign()` produced the expected outputs when consumed as a
downstream module (bazel_dep + local_path_override), covering both a plain
set of files and an oci_image.

A file source is signed into a file, so `signed_outputs` is the three files
it was given rather than a directory holding them. A directory source stays a
directory, which is what `signed_oci_image` is.
"""

import argparse
import pathlib
import unittest


class VerifyOutputsTest(unittest.TestCase):
    def test_signed_outputs(self):
        expected = {
            "bin/app.exe": "consumer exe\n",
            "docs/readme.txt": "consumer docs\n",
            "nested/a/b/guide.txt": "consumer nested\n",
        }

        outputs = {}
        for rootpath in FLAGS.signed_outputs:
            path = pathlib.Path(rootpath)
            self.assertTrue(path.is_file(), f"expected an output file: {path}")
            for rel in expected:
                if path.as_posix().endswith("/" + rel):
                    outputs[rel] = path

        # No certificate is configured, so every file is copied through
        # unsigned and nothing else is produced beside it.
        self.assertEqual(sorted(outputs), sorted(expected))
        self.assertEqual(len(FLAGS.signed_outputs), len(expected))
        for rel, content in expected.items():
            self.assertEqual(outputs[rel].read_text(), content)

    def test_signed_oci_image(self):
        if not FLAGS.signed_oci_image:
            self.skipTest("oci_image is not built on this platform")
        signed_oci_image_dir = pathlib.Path(FLAGS.signed_oci_image)
        self.assertTrue((signed_oci_image_dir / "oci-layout").is_file())
        self.assertTrue((signed_oci_image_dir / "index.json").is_file())
        self.assertTrue((signed_oci_image_dir / "blobs" / "sha256").is_dir())


FLAGS = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("signed_outputs", nargs="+")
    parser.add_argument("--signed-oci-image", default="")
    FLAGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
