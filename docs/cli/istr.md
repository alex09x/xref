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
xref: load 930.4µs, total 3.3ms
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
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
