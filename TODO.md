# TODO

Known gaps and deferred decisions in `rules_signing`. Each entry records what
was found, why it was left alone, and what resolving it would involve.

## 1. Decide whether to pass `-nolegacy` to osslsigncode

Every `osslsigncode` invocation prints a pair of warnings:

```
Warning: Legacy mode disabled
```

The cause is not a problem with the certificate or the invocation. The
`osslsigncode` binary fetched by the toolchain is statically linked with
dynamic loading disabled, so the OpenSSL 3.x legacy provider
(`ossl-modules/legacy.so`) can never be loaded, and the attempt to load it at
startup always fails.

The only real consequence is that PKCS#12 files encrypted with legacy ciphers
(for example `PBE-SHA1-RC2-40` or 3DES) cannot be read. This was confirmed
empirically: a modern PBES2/AES PKCS#12 signs successfully, while a legacy
RC2-40 one fails with `unsupported ... RC2-40-CBC`.

Passing `-nolegacy` silences both warning lines, and the resulting signature
still verifies. It was verified to be safe but not applied, because it trades
a confusing-but-harmless warning for silently narrowing what the tool accepts,
and that is a user-facing decision.

**To resolve:** either add `-nolegacy` in `sign_with_osslsigncode`
(`signing/private/tools/sign_tool.py`) and note the legacy-PKCS#12 limitation
in the README, or leave it and document what the warning means so users stop
reporting it.

## 2. Remove or document the dead `-legacy` retry in `pkcs12_to_pem`

`pkcs12_to_pem` in `signing/private/tools/sign_tool.py` retries the conversion
with `-legacy` when the first attempt fails, on the assumption that the
certificate uses a cipher only reachable through OpenSSL 3.x's legacy
provider.

That retry can never succeed with the toolchain as configured: the OpenSSL
build from the Bazel Central Registry reports only the `default` provider, so
`-legacy` fails the same way the original command did. The fallback therefore
only converts one error message into a slightly more confusing one.

**To resolve:** either drop the retry and let the original error surface, or
keep it and add a comment explaining that it exists for
externally-supplied OpenSSL binaries that do ship the legacy provider. Do not
leave it as-is without a comment, since it currently reads as working
behaviour.

## 3. Real signing of `.dmg` and `.pkg` is unverified

`sign_verify_test` signs and then genuinely verifies PE binaries, Mach-O
binaries, `.app` bundles, detached cosign blobs, and OCI layouts. Apple disk
images and installer packages are handled by the rules but are covered only by
passthrough/layout tests, not by a real signature check.

The blocker is that neither container can be built hermetically on Linux:
producing them requires Apple tooling (`hdiutil`, `productbuild`), so there is
nothing valid to hand to `rcodesign` in CI as it currently runs.

**To resolve:** either add a macOS CI runner and build the fixtures natively,
or find a way to construct a minimal valid UDIF/xar container from a checked-in
template. Until then, treat `.dmg` and `.pkg` support as untested rather than
working.

## 4. Tool failures surface as raw tracebacks

Every signing tool is invoked through `run_cmd`, and a non-zero exit becomes an
unhandled `subprocess.CalledProcessError`. What the user sees is a Python
traceback ending in a return code, with the tool's own diagnostics somewhere
above it in the build log.

Common, entirely recoverable mistakes -- a wrong certificate password, an
expired certificate, an unreachable timestamp authority -- are all presented
this way, with nothing pointing at which attribute to change.

**To resolve:** catch `CalledProcessError` at the signing entry points and
re-raise with the tool name, the artifact being signed, and the tool's captured
output, so the failure names the thing the user has to fix.
