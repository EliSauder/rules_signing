"""Verifies the `certificate_*` conversion rules work for a downstream module."""

import argparse
import pathlib
import unittest


class VerifyCertificateFormatsTest(unittest.TestCase):
    def test_pem(self):
        text = pathlib.Path(FLAGS.pem).read_text()
        self.assertIn("PRIVATE KEY", text)
        self.assertIn("BEGIN CERTIFICATE", text)

    def test_pkcs12_outputs_are_not_empty(self):
        for path in (FLAGS.p12, FLAGS.keystore):
            self.assertGreater(pathlib.Path(path).stat().st_size, 0, path)

    def test_snk(self):
        names = {pathlib.Path(p).name: pathlib.Path(p) for p in FLAGS.snk}
        self.assertGreater(names["dev_cert_snk.snk"].stat().st_size, 0)
        self.assertGreater(names["dev_cert_snk.public.snk"].stat().st_size, 0)

    def test_cosign_keypair(self):
        by_name = {pathlib.Path(p).name: pathlib.Path(p) for p in FLAGS.keypair}
        self.assertIn("SIGSTORE PRIVATE KEY", by_name["dev_cert_keypair.key"].read_text())
        self.assertIn("PUBLIC KEY", by_name["dev_cert_keypair.pub"].read_text())


FLAGS = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("pem", "p12", "keystore"):
        parser.add_argument("--" + name, required=True)
    for name in ("snk", "keypair"):
        parser.add_argument("--" + name, nargs="+", required=True)
    FLAGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
