SigningCertificateInfo = provider(
    doc = "Signing material and interpolation settings.",
    fields = {
        "certificate": "Optional File containing already-resolved cert/key " +
                       "material: either the direct `certificate_file`, or " +
                       "the output of stamping and decoding a `certificate` " +
                       "template. Consumers never see raw templates.",
        "ca_file": "Optional File containing the issuing CA chain.",
        "password": "Optional password template with {KEY} placeholders.",
        "password_env": "Optional env var name containing password.",
        "identity": "Optional Apple identity template with {KEY} placeholders.",
        "stamp_defaults": "Dict of default values for unresolved stamp keys.",
    },
)
