"""Missing signing adapters must fail only for inputs that require them."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")

def _missing_jarsigner_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "rules_signing: the jarsigner toolchain is required but was not resolved")
    asserts.expect_failure(env, "@rules_signing//signing/toolchains:jarsigner_toolchain")
    return analysistest.end(env)

missing_jarsigner_test = analysistest.make(
    _missing_jarsigner_test_impl,
    expect_failure = True,
)

def _missing_codesign_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "rules_signing: the codesign toolchain is required but was not resolved")
    asserts.expect_failure(env, "@rules_signing//signing/toolchains:codesign_toolchain")
    return analysistest.end(env)

missing_codesign_test = analysistest.make(
    _missing_codesign_test_impl,
    expect_failure = True,
)
