# xref where

Functions passing source locations whose file contains a pattern (and optionally at one line).

Extracts core::panic::Location structs from .rodata even after strip --strip-all, linking stripped functions back to exact file:line:col anchors.

## Usage

<!-- xref:usage where -->
```text
xref where [OPTIONS] <PATTERN>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options where -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<PATTERN>` | Substring of the source file path. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--line <LINE>` | Only locations on this line. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Where src/loops.rs

All stripped functions referencing panic locations in src/loops.rs.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped where src/loops.rs
```

```text output
0x951c0..0x95300  src/loops.rs:142
0xc7d60..0xc7fbf  src/loops.rs:45
0xc7fc0..0xd0a9d  src/loops.rs:108  src/loops.rs:131  src/loops.rs:132  src/loops.rs:139  src/loops.rs:152  src/loops.rs:157  src/loops.rs:158  src/loops.rs:186  src/loops.rs:202  src/loops.rs:203  src/loops.rs:209  src/loops.rs:210  src/loops.rs:65  src/loops.rs:69  src/loops.rs:77  src/loops.rs:85  src/loops.rs:87
0xd0aa0..0xd0d73  src/loops.rs:33
0x120d00..0x120d3e  src/loops.rs:142
21 locations, 21 references
```

```stderr
xref: load 484.1µs, total 2.2ms
```
<!-- /xref -->

### Where src/image.rs --line 46

Pinpoints the exact stripped function containing src/image.rs line 46.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped where src/image.rs --line 46
```

```text output
0x9ef60..0x9f518  src/image.rs:46
1 locations, 1 references
```

```stderr
xref: load 515.0µs, total 2.2ms
```
<!-- /xref -->

## Reading the output

- One line per function that passes a panic location in a matching file: the function range and every `file:line` it passes. The last line counts locations and references.
- `--line N` keeps only locations on that line.

## Limits

- A function appears only if code compiled from that file can panic there; inlining can place a file's locations in a caller from another file.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
