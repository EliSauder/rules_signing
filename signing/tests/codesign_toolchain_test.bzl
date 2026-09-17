"""Coverage for custom rcodesign binaries and their runtime files."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//signing:defs.bzl", "sign")
load("//signing/toolchains:toolchains.bzl", "codesign_toolchain")

def _binary_impl(ctx):
    tool = ctx.actions.declare_file(ctx.label.name + "/rcodesign")
    support = ctx.actions.declare_file(ctx.label.name + "/support")
    ctx.actions.write(tool, "test rcodesign")
    ctx.actions.write(support, "test runtime file")
    return [DefaultInfo(
        files = depset([tool]),
        runfiles = ctx.runfiles(files = [support]),
    )]

_binary = rule(implementation = _binary_impl)

def _adapter_test_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    tc = target[platform_common.ToolchainInfo]
    asserts.equals(env, "rcodesign", tc.tool.basename)
    asserts.equals(env, ["entitlements.plist", "rcodesign", "support"], sorted([f.basename for f in tc.data.to_list()]))
    asserts.equals(env, tc.data.to_list(), target[DefaultInfo].files.to_list())
    asserts.equals(env, tc.data.to_list(), target[DefaultInfo].default_runfiles.files.to_list())
    return analysistest.end(env)

_adapter_test = analysistest.make(_adapter_test_impl)

def _action_inputs_test_impl(ctx):
    env = analysistest.begin(ctx)
    actions = [a for a in analysistest.target_actions(env) if a.mnemonic == "SignTree"]
    asserts.equals(env, 1, len(actions))
    if actions:
        names = [f.basename for f in actions[0].inputs.to_list()]
        for name in ["rcodesign", "support", "entitlements.plist"]:
            asserts.true(env, name in names, "missing codesign action input: " + name)
    return analysistest.end(env)

_action_inputs_test = analysistest.make(
    _action_inputs_test_impl,
    config_settings = {
        "//command_line_option:extra_toolchains": ["//signing/tests:custom_codesign_toolchain"],
    },
)

def codesign_toolchain_test_suite(name):
    _binary(name = name + "_binary")
    codesign_toolchain(
        name = name + "_adapter",
        codesign = ":" + name + "_binary",
        data = ["//signing/tests:testdata/entitlements.plist"],
    )
    native.toolchain(
        name = "custom_codesign_toolchain",
        toolchain = ":" + name + "_adapter",
        toolchain_type = "//signing/toolchains:codesign_toolchain_type",
    )
    _adapter_test(
        name = name + "_adapter_test",
        target_under_test = ":" + name + "_adapter",
    )
    native.filegroup(
        name = name + "_src",
        srcs = ["//signing/tests:testdata/entitlements.plist"],
    )
    sign(
        name = name + "_sign",
        src = ":" + name + "_src",
        tool = "codesign",
    )
    _action_inputs_test(
        name = name + "_action_inputs_test",
        target_under_test = ":" + name + "_sign",
    )
    native.test_suite(
        name = name,
        tests = [name + "_adapter_test", name + "_action_inputs_test"],
    )
