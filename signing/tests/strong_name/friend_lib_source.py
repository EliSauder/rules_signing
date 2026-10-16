"""Writes a C# source granting its internals to `friend_app` by public key."""

import sys

public_key_path, out_path = sys.argv[1:]
with open(public_key_path, "rb") as handle:
    public_key = handle.read().hex()
with open(out_path, "w") as handle:
    handle.write(
        "[assembly: System.Runtime.CompilerServices.InternalsVisibleTo(\n"
        '    "friend_app, PublicKey={}")]\n'
        "\n"
        "internal static class Secret\n"
        "{{\n"
        '    internal static string Message() => "friend access granted";\n'
        "}}\n".format(public_key)
    )
