load(
    "//signing/private:common.bzl",
    "add_cert_args",
    "cert_info",
)
load("//signing:providers.bzl", "SigningCertificateInfo")

_OSSLSIGNCODE_TOOLCHAIN = "//signing/toolchains:osslsigncode_toolchain_type"
_CODESIGN_TOOLCHAIN = "@codesign.bzl//toolchain:toolchain_type"

_OSSLSIGNCODE_EXT = [
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".cat",
    ".ocx",
    ".efi",
    ".appx",
    ".cab",
    ".ps1",
    ".ps1xml",
    ".psc1",
    ".psd1",
    ".psm1",
    ".cdxml",
    ".mof",
    ".js",
]

_CODESIGN_EXT = [
    ".app",
    ".pkg",
    ".dmg",
]

def _detect_tool(path):
    p = path.lower()
    for ext in _OSSLSIGNCODE_EXT:
        if p.endswith(ext):
            return "osslsigncode"
    for ext in _CODESIGN_EXT:
        if p.endswith(ext):
            return "codesign"
    return ""

def _needs_toolchain(srcs, selected_tool, tool_kind):
    if selected_tool == tool_kind:
        return True
    if selected_tool != "auto":
        return False
    for f in srcs:
        if _detect_tool(f.short_path) == tool_kind:
            return True
    return False

def _sign_impl(ctx):
    srcs = sorted(ctx.attr.src[DefaultInfo].files.to_list(), key = lambda f: f.short_path)
    out_name = ctx.attr.out if ctx.attr.out else "{}.signed".format(ctx.label.name)
    out_dir = ctx.actions.declare_directory(out_name)
    cert = cert_info(ctx)

    args = ctx.actions.args()
    args.add("--mode", "tree")
    args.add("--out-dir", out_dir.path)
    args.add("--tool", ctx.attr.tool)

    osslsigncode_tc = ctx.toolchains[_OSSLSIGNCODE_TOOLCHAIN]
    needs_osslsigncode = _needs_toolchain(srcs, ctx.attr.tool, "osslsigncode")
    if needs_osslsigncode and (osslsigncode_tc == None or not hasattr(osslsigncode_tc, "tool")):
        fail("osslsigncode toolchain is required but was not resolved")
    osslsigncode_tool = osslsigncode_tc.tool.path if osslsigncode_tc and hasattr(osslsigncode_tc, "tool") else ""
    args.add("--osslsigncode-tool", osslsigncode_tool)

    codesign_tc = ctx.toolchains[_CODESIGN_TOOLCHAIN]
    needs_codesign = _needs_toolchain(srcs, ctx.attr.tool, "codesign")
    if needs_codesign and codesign_tc == None:
        fail("codesign toolchain is required but was not resolved")
    codesign_tool = ""
    if codesign_tc != None:
        if hasattr(codesign_tc, "codesign") and hasattr(codesign_tc.codesign, "tool"):
            codesign_tool = codesign_tc.codesign.tool.path
        elif hasattr(codesign_tc, "tool"):
            codesign_tool = codesign_tc.tool.path
    if needs_codesign and not codesign_tool:
        fail("codesign toolchain is resolved but does not expose an executable tool")
    args.add("--codesign-tool", codesign_tool)

    if ctx.attr.timestamp_url:
        args.add("--timestamp-url", ctx.attr.timestamp_url)
    if ctx.attr.description:
        args.add("--name", ctx.attr.description)
    if ctx.attr.url:
        args.add("--url", ctx.attr.url)
    if ctx.attr.options:
        args.add("--options", ",".join(ctx.attr.options))
    if ctx.file.entitlements:
        args.add("--entitlements", ctx.file.entitlements.path)

    for f in srcs:
        args.add("--rel", f.short_path)
        args.add("--src", f.path)

    extra_inputs = add_cert_args(ctx, args, cert)
    inputs = srcs + extra_inputs
    tools = [ctx.executable._tool]
    if ctx.file.entitlements:
        inputs.append(ctx.file.entitlements)

    if osslsigncode_tc != None and hasattr(osslsigncode_tc, "tool"):
        inputs.append(osslsigncode_tc.tool)
    if codesign_tc != None:
        if hasattr(codesign_tc, "codesign") and hasattr(codesign_tc.codesign, "tool"):
            inputs.append(codesign_tc.codesign.tool)
        elif hasattr(codesign_tc, "tool"):
            inputs.append(codesign_tc.tool)

    ctx.actions.run(
        executable = ctx.executable._tool,
        inputs = depset(inputs),
        tools = tools,
        outputs = [out_dir],
        arguments = [args],
        mnemonic = "SignTree",
        progress_message = "Signing output tree for {}".format(ctx.label),
    )

    return [DefaultInfo(files = depset([out_dir]))]

sign = rule(
    implementation = _sign_impl,
    doc = "Signs all files from `src`, preserving relative output structure.",
    attrs = {
        "src": attr.label(
            mandatory = True,
            providers = [[DefaultInfo]],
            cfg = "target",
        ),
        "out": attr.string(doc = "Optional output directory artifact name."),
        "tool": attr.string(
            default = "auto",
            values = ["osslsigncode", "codesign", "auto"],
        ),
        "certificate": attr.label(
            providers = [[SigningCertificateInfo]],
        ),
        "timestamp_url": attr.string(),
        "description": attr.string(doc = "Signature description when supported."),
        "url": attr.string(doc = "Publisher URL when supported."),
        "options": attr.string_list(
            default = ["runtime"],
            doc = "codesign --options values.",
        ),
        "entitlements": attr.label(allow_single_file = True),
        "_tool": attr.label(
            default = "//signing/private/tools:sign_tool",
            executable = True,
            cfg = "exec",
        ),
    },
    toolchains = [
        config_common.toolchain_type(_OSSLSIGNCODE_TOOLCHAIN),
        config_common.toolchain_type(_CODESIGN_TOOLCHAIN, mandatory = False),
    ],
)
