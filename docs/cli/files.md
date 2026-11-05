# xref files

Distinct source files of the panic locations (optionally containing a pattern), with counts.

Extracts core::panic::Location structs from .rodata even after strip --strip-all, linking stripped functions back to exact file:line:col anchors.

## Usage

<!-- xref:usage files -->
```text
xref files [PATTERN]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options files -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `[PATTERN]` | Substring of the source file path; all files when omitted. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Files loops.rs

Counts embedded panic location descriptors matching loops.rs.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped files loops.rs
```

```text output
    21  src/loops.rs
1 files
```

```stderr
xref: load 734.4µs, total 1.6ms
```
<!-- /xref -->

## Reading the output

- One line per distinct source file named by a panic location in the binary, with the number of locations; the last line counts the files.

## Limits

- Only files that appear in panic `Location` descriptors are known: code that cannot panic leaves no trace, and dependencies appear with their own relative paths.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
