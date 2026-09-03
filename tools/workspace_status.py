#!/usr/bin/env python3
"""Workspace status script for rules_signing's own tests.

See the "Stamping" section of the README and //signing/tests:stamp_attr_test.
Bazel runs this on every build, with the working directory set to the
workspace root, regardless of --stamp/--nostamp, and writes lines whose key
starts with STABLE_ into bazel-out/stable-status.txt -- unlike the rest of
the status file, STABLE_ keys are never redacted to a constant.

`sign`/`certificate`'s `stamp` attribute controls whether a target actually
reads that file, so this script's only job is to make a real value available
to prove out that plumbing, not to fake production stamping behavior.

Written in Python rather than shell so the same file works unmodified on
every CI platform (GNU/BSD `base64` disagree on CLI flags, and Bazel invokes
workspace_status_command directly rather than through a shell, so a shebang
in a plain .sh is never honored on Windows to begin with).
"""

from __future__ import annotations

import base64
import pathlib
import sys


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    cert_file = repo_root / "signing" / "tests" / "testdata_certs" / "generic.p12"
    encoded = base64.b64encode(cert_file.read_bytes()).decode("ascii")
    print("STABLE_RULES_SIGNING_TEST_CERT_B64 {}".format(encoded))
    return 0


if __name__ == "__main__":
    sys.exit(main())
