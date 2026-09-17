# How `rules_signing` uses aspects

This project relies on exactly one Bazel [aspect](https://bazel.build/extend/aspects):
`binary_format_aspect`, defined in `signing/private/detect.bzl`. This document
explains what it does, why an aspect is the right tool, and how it ties into
the rule table in `signing/private/binary_kinds.bzl`.

## The problem

The `sign` rule has to decide, during **analysis** — before any file is
built — which of its `src`'s outputs are native binaries (Windows PE, macOS
Mach-O, or a signable `.jar`), so it can:

1. pick the right signer for each file, and
2. declare correctly-shaped signed outputs.

Reading the file to find out is not an option: it does not exist yet.
What *is* available at analysis time is **the rule that will build the
file** and **the configuration it will be built in** — and between them
those give a better answer than the bytes would anyway (a `cc_binary`
produces a real native binary; a `py_binary` produces a launcher script that
merely looks like one).

## The aspect: `binary_format_aspect`

```
                     sign(src = ":my_app")
                              │
                              │ attr.label(aspects = [binary_format_aspect])
                              ▼
        ┌───────────────────────────────────────────────────┐
        │ target: cc_binary / py_binary / scala_binary / ... │
        │                                                     │
        │  _aspect_impl(target, ctx):                         │
        │   1. target already provides BinaryFormatInfo?      │
        │        → leave it alone, return []                  │
        │   2. entry = lookup(ctx.rule.kind)  ───────────────┐ │
        │   3. classify target's outputs using entry          │
        │   4. fmt = entry.format OR _platform_format(ctx)     │
        │        (reads target_platform_has_constraint:       │
        │         windows / macos, from the TARGET's OWN      │
        │         configuration)                               │
        └──────────────────────┬──────────────────────────────┘
                                ▼
              BinaryFormatInfo(formats = {File: "pe"|"macho"|"jar"})
                                │
                                ▼
        sign rule reads it via binary_formats(ctx.attr.src)
        → chooses signer, declares matching outputs
```

**Why an aspect, and not just reading a provider off the dependency?**

- The aspect runs **in each dependency's own configuration**. This is what
  makes cross-compiled signing correct: a `cc_binary` transitioned to
  Windows reports `pe` even when the `sign` target itself is configured for
  Linux (exercised by `signing/tests/cross.bzl`).
- `attr_aspects = forward_attr_names()` limits how far the aspect
  propagates — only into the attributes some table row actually forwards
  through (see below) — instead of walking the whole transitive graph
  beneath the signed target, which would be wasted work.
- A rule can pre-empt the whole table by returning its own
  `BinaryFormatInfo` directly; the aspect detects this (`if BinaryFormatInfo
  in target: return []`) and leaves it untouched. This keeps the mechanism
  open to rules the table has never heard of.

## The table: `RULE_KINDS` (`binary_kinds.bzl`)

The aspect is the engine; the table is its knowledge base. They are tied
together by one call: `lookup(ctx.rule.kind)`.

```
                binary_kinds.bzl                            detect.bzl
   ┌─────────────────────────────────────┐      ┌──────────────────────────────┐
   │ RULE_KINDS = {                       │      │ _aspect_impl(target, ctx):   │
   │   "cc_binary": executable(),         │      │                              │
   │   "cc_shared_library": all_outputs(),│ ───▶ │  entry = lookup(              │
   │   "java_binary": jar_outputs(),      │ keyed │      ctx.rule.kind)          │
   │   "filegroup": forward("srcs"),      │ by    │  # entry: kind, attrs,       │
   │   "py_binary": not_native(...),      │ rule  │  #        format,           │
   │   ...                                │ name  │  #        names_are_evidence │
   │ }                                    │ string│                              │
   └─────────────────────────────────────┘      └──────────────────────────────┘
```

Rules are matched by `ctx.rule.kind` — the rule's own name, not a wrapping
macro's — as a plain string. Nothing here loads a ruleset, which means:

- a table row can describe `go_binary` without `rules_go` being in the
  module graph, and
- a build that has never heard of Rust or Kotlin pays nothing for those
  rows.

### The five row kinds, and how the aspect handles each

| Table constructor | Meaning | Aspect's handling |
|---|---|---|
| `executable()` | rule's `files_to_run.executable` is a native binary | verdict applied only to that one file |
| `all_outputs()` | every `DefaultInfo` file is a native binary | verdict applied to every output |
| `jar_outputs()` | rule emits a `.jar` beside a non-jar launcher | verdict applied only to `*.jar` outputs; everything else forced `NOT_NATIVE` |
| `forward("attr", ...)` | rule passes another target's bytes through unchanged (copy, rename, wrapper) | aspect recurses into that attribute's dependency's own `BinaryFormatInfo` via `_forwarded()`, matching by file identity, then by position for renamed copies |
| `not_native(reason)` | rule's outputs are conclusively not native binaries | every output forced `NOT_NATIVE` |
| *(no row for this kind)* | rule unknown to this project | `lookup()` returns `None`; aspect returns an empty `BinaryFormatInfo({})` — no verdict, not a guess |

A `not_native()` verdict is deliberately **not the same as an absent row**:
an absent row means "no opinion," while `not_native()` conclusively marks
every output, which matters for rules like `native_binary` that name their
Windows launcher `<name>.exe` even on Linux — without a forced verdict, a
naive extension-based fallback would misread that stub as a real PE and
hand it to `osslsigncode`, corrupting it.

### Two fields that connect table and aspect directly

- **`entry.format`** — most rows leave this `None`, so the aspect derives
  PE vs. Mach-O from the *target's own build configuration*
  (`_platform_format(ctx)`). A few rows pin it explicitly (e.g. .NET
  assemblies are always `PE`, regardless of host, because a managed
  assembly's format never depends on target platform).
- **`entry.attrs`** — only set by `forward(...)` rows, naming the
  attribute(s) that carry the real bytes through (`"src"`, `"srcs"`,
  `"target"`, `"binary"`, `"actual"`, ...). `forward_attr_names()` unions
  every attribute name across the whole table, and that union becomes the
  aspect's own `attr_aspects`. **In other words: the table itself decides
  how far the aspect is allowed to propagate down the dependency graph** —
  the aspect only walks into attributes some rule in the table actually
  needs it to.

## Summary

- One aspect (`binary_format_aspect`), applied to one attribute (`src`) on
  one rule (`sign`).
- The aspect turns "what rule built this file, in what configuration" into
  "what native binary format is this," entirely during analysis.
- The table (`RULE_KINDS`) is pure data — a string-keyed dictionary with no
  loaded dependencies on any ruleset — and the aspect is the only code that
  interprets it, via `lookup(ctx.rule.kind)` and the five row constructors
  above.
- Cross-compilation correctness comes from the aspect reading each
  dependency's *own* configuration rather than the signing target's.
