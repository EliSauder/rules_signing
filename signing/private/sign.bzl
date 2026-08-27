load(":sign_codesign.bzl", "sign_codesign")
load(":sign_osslsigncode.bzl", "sign_osslsigncode")

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

def _detect(src):
    s = src.lower()
    for ext in _OSSLSIGNCODE_EXT:
        if s.endswith(ext)
            return "osslsigncode"
    for ext in _CODESIGN_EXT:
        if s.endswith(ext)
            return "codesign"

def _sign_files(name, visibility, di, tool, certificate, **kwargs):
    for f in di.files:
        t = tool
        if t == "auto":
            t = _detect(f.path)

        if t == "osslsigncode":
            sign_osslsigncode(
                name = name,
                src = f,
                certificate = certificate,
                **kwargs,
            )
        elif t == "codesign":
            sign_codesign(
                name = name,
                src = f,
                certificate = certificate,
                **kwargs,
            )
        else:
            fail("unknown signing tool {}".format(t))

def _sign_impl(name, visibility, src, tool, certificate):
    if DefaultInfo in src:
        di = src[DefaultInfo]
        _sign_files(name, visibility, src, tool, certificate):

    if tool == "auto":
        tool = _detect(src.path if tool == "auto" else name)

sign = macro(
    implementation = _sign_impl,
    attrs = {
        src = attr.label(
            mandatory = True,
            allow_files = True,
            providers = [
                [DefaultInfo],
            ],
            cfg = "target",
        ),
        tool = attr.string(
            default = "auto",
            values = [
                "osslsigncode",
                "codesign",
                "auto",
            ]
        ),
        certificate = attr.label(
            mandatory = True,
            providers = [
                [SigningCertificateInfo],
            ]
        ),
    },
)
