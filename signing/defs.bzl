load(
    "//signing/private:certificate_formats.bzl",
    _certificate_keypair = "certificate_keypair",
    _certificate_keystore = "certificate_keystore",
    _certificate_p12 = "certificate_p12",
    _certificate_pem = "certificate_pem",
    _certificate_snk = "certificate_snk",
)
load("//signing/private:certificate.bzl", _certificate = "certificate")
load(
    "//signing/private:self_signed_certificate.bzl",
    _self_signed_certificate = "self_signed_certificate",
)
load("//signing/private:sign.bzl", _sign = "sign")

sign = _sign
certificate = _certificate
self_signed_certificate = _self_signed_certificate
certificate_pem = _certificate_pem
certificate_p12 = _certificate_p12
certificate_keystore = _certificate_keystore
certificate_snk = _certificate_snk
certificate_keypair = _certificate_keypair
