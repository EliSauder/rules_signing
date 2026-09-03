#!/usr/bin/env bash
# Workspace status script for rules_signing's own tests (see the "Stamping"
# section of the README and //signing/tests:stamp_attr_test). Bazel runs this
# on every build, with the working directory set to the workspace root,
# regardless of --stamp/--nostamp, and writes lines whose key starts with
# STABLE_ into bazel-out/stable-status.txt -- unlike the rest of the status
# file, STABLE_ keys are never redacted to a constant.
#
# `sign`/`certificate`'s `stamp` attribute controls whether a target actually
# reads that file, so this script's only job is to make sure a real value is
# available to prove out that plumbing, not to fake production stamping
# behavior.
set -euo pipefail

# Bazel runs this with the working directory set to the workspace root, so
# the fixture can be addressed with a plain workspace-relative path.
cert_file="signing/tests/testdata_certs/generic.p12"
echo "STABLE_RULES_SIGNING_TEST_CERT_B64 $(base64 -w0 "$cert_file")"
