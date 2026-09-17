"""Analysis coverage for adapting JDK runtime providers."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//signing/toolchains:toolchains.bzl", "jarsigner_toolchain")

def _runtime_impl(ctx):
    files = []
    for name in ctx.attr.files:
        f = ctx.actions.declare_file(ctx.label.name + "/" + name)
        ctx.actions.write(f, "test JDK artifact")
        files.append(f)
    return [platform_common.ToolchainInfo(java_runtime = struct(files = depset(files)))]

_runtime = rule(
    implementation = _runtime_impl,
    attrs = {"files": attr.string_list()},
)

def _adapter_test_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    tc = target[platform_common.ToolchainInfo]
    asserts.equals(env, ctx.attr.expected_tool, tc.tool.basename)
    asserts.equals(env, 3, len(tc.data.to_list()))
    asserts.true(env, tc.tool in tc.data.to_list())
    asserts.equals(env, tc.java_runtime.files.to_list(), tc.data.to_list())
    asserts.equals(env, tc.data.to_list(), target[DefaultInfo].files.to_list())
    asserts.equals(env, tc.data.to_list(), target[DefaultInfo].default_runfiles.files.to_list())
    return analysistest.end(env)

_adapter_test = analysistest.make(
    _adapter_test_impl,
    attrs = {"expected_tool": attr.string()},
)

def _missing_tool_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "does not contain jarsigner")
    return analysistest.end(env)

_missing_tool_test = analysistest.make(_missing_tool_test_impl, expect_failure = True)

def jarsigner_toolchain_test_suite(name):
    tests = []
    for suffix, tool in [("unix", "jarsigner"), ("windows", "jarsigner.exe")]:
        _runtime(
            name = name + "_" + suffix + "_runtime",
            files = ["bin/" + tool, "bin/keytool", "lib/support"],
        )
        jarsigner_toolchain(
            name = name + "_" + suffix + "_adapter",
            java_runtime = ":" + name + "_" + suffix + "_runtime",
        )
        test = name + "_" + suffix + "_test"
        _adapter_test(
            name = test,
            target_under_test = ":" + name + "_" + suffix + "_adapter",
            expected_tool = tool,
        )
        tests.append(test)

    _runtime(name = name + "_jre", files = ["bin/java"])
    jarsigner_toolchain(
        name = name + "_jre_adapter",
        java_runtime = ":" + name + "_jre",
        tags = ["manual"],
    )
    _missing_tool_test(
        name = name + "_missing_tool_test",
        target_under_test = ":" + name + "_jre_adapter",
    )
    tests.append(name + "_missing_tool_test")
    native.test_suite(name = name, tests = tests)
