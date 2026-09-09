"""Verifies that `sign()` produced the expected output tree when consumed as
a downstream module (bazel_dep + local_path_override), covering both a plain
directory of files and an oci_image.
"""

import argparse
import pathlib
import unittest


class VerifyOutputsTest(unittest.TestCase):
    def test_signed_outputs(self):
        signed_outputs_dir = pathlib.Path(FLAGS.signed_outputs)
        self.assertEqual(
            (signed_outputs_dir / "bin" / "app.exe").read_text(),
            "consumer exe\n",
        )
        self.assertEqual(
            (signed_outputs_dir / "docs" / "readme.txt").read_text(),
            "consumer docs\n",
        )
        self.assertEqual(
            (signed_outputs_dir / "nested" / "a" / "b" / "guide.txt").read_text(),
            "consumer nested\n",
        )

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
    parser.add_argument("--signed-outputs", required=True)
    parser.add_argument("--signed-oci-image", default="")
    FLAGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
