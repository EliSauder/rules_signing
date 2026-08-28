# Consumer module utilization test

This directory is a standalone Bazel module that consumes `rules_signing`.

From this directory, run:

```bash
bazel --nohome_rc clean --expunge
bazel --nohome_rc build //:signed_outputs
```

This validates real module consumption through `bazel_dep(...)` + `local_path_override(...)` and produces:

- `bazel-bin/signed_outputs.signed/bin/app.exe`
- `bazel-bin/signed_outputs.signed/docs/readme.txt`
- `bazel-bin/signed_outputs.signed/nested/a/b/guide.txt`
