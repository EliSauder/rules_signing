"""Signing converts the certificate with the action the format rules use."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")

def _check(env, expected_formats):
    actions = analysistest.target_actions(env)
    converts = [a for a in actions if a.mnemonic == "ConvertCertificate"]
    signs = [a for a in actions if a.mnemonic not in ("ConvertCertificate", "FileWrite", "TemplateExpand")]
    formats = {}
    for action in converts:
        argv = action.argv
        fmt = ""
        for i, arg in enumerate(argv):
            if arg == "--convert-format":
                fmt = argv[i + 1]
        formats[fmt] = action

    asserts.equals(env, sorted(expected_formats), sorted(formats.keys()))
    sign_inputs = []
    for action in signs:
        sign_inputs.extend(action.inputs.to_list())
    for fmt, action in formats.items():
        for out in action.outputs.to_list():
            asserts.true(env, out in sign_inputs, "{} conversion is not a signing input".format(fmt))

def _jar_and_detached_test_impl(ctx):
    env = analysistest.begin(ctx)
    _check(env, ["cosign", "keystore"])
    return analysistest.end(env)

jar_and_detached_test = analysistest.make(_jar_and_detached_test_impl)

def _detached_only_test_impl(ctx):
    env = analysistest.begin(ctx)
    _check(env, ["cosign"])
    return analysistest.end(env)

detached_only_test = analysistest.make(_detached_only_test_impl)
