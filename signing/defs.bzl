load("//signing/private:certificate.bzl", _certificate = "certificate")
load("//signing/private:sign.bzl", _sign = "sign")
load("//signing/private:sign_codesign.bzl", _sign_codesign = "sign_codesign")
load("//signing/private:sign_osslsigncode.bzl", _sign_osslsigncode = "sign_osslsigncode")

sign = _sign
sign_codesign = _sign_codesign
sign_osslsigncode = _sign_osslsigncode
certificate = _certificate
