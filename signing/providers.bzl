SigningCertificateInfo = provider(
    doc = "Signing material and interpolation settings.",
    fields = {
        "certificate": "Optional File containing cert/key material.",
        "ca_file": "Optional File containing the issuing CA chain.",
        "cert": "Optional certificate/key template string with {STAMP} placeholders.",
        "cert_encoding": "Template encoding: path|base64.",
        "password": "Optional password template with {STAMP} placeholders.",
        "password_env": "Optional env var name containing password.",
        "identity": "Optional Apple identity template with {STAMP} placeholders.",
        "stamp_defaults": "Dict of default values for unresolved stamp keys.",
    },
)
