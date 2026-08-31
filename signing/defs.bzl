load("//signing/private:certificate.bzl", _certificate = "certificate")
load("//signing/private:sign.bzl", _sign = "sign")

sign = _sign
certificate = _certificate
