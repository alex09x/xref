# xref istr

Find strings that a function builds from immediate stores instead of reading
them from `.rodata`: compilers write short strings with `movabs` / `mov [mem],
imm` instructions, so a text search of the data sections misses them. `istr
TEXT` is the same search as [`refs --inline TEXT`](refs.md).

## Usage

<!-- xref:usage istr -->
```text
xref istr <TARGETS>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options istr -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<TARGETS>...` | Texts to search for. |  |
<!-- /xref -->

## Examples

### A string built inline

<!-- xref:run -->
```console
$ xref -b xref.stripped istr "while ("
```

```text output
0xcfa1b  in 0xc7fc0..0xd0a9d  "while (" (7/7 bytes at 0xcfa1b)
1 hits
```

```stderr
xref: load 541.3µs, total 1.9ms
```
<!-- /xref -->

The line gives the first store instruction, the function range that contains
it, the text, and how many of its bytes were found in the stores
(`7/7 bytes at 0xcfa1b`).

## Limits

- Only stores of immediate values are followed; text assembled from registers or
  copied from elsewhere is not found.
- A partial match (fewer bytes than the text) is reported with its byte count.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
