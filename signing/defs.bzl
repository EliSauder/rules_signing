load("//signing/private:certificate.bzl", _certificate = "certificate")
load(
    "//signing/private:self_signed_certificate.bzl",
    _self_signed_certificate = "self_signed_certificate",
)
load("//signing/private:sign.bzl", _sign = "sign")

sign = _sign
certificate = _certificate
self_signed_certificate = _self_signed_certificate
