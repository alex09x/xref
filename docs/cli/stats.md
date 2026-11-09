# xref stats

Functions, code size, data pointers, imports and panic locations.

Summarizes .eh_frame function boundaries, code bytes, relocated pointers, imports, symbol count, and Rust panic locations without writing an index.

## Usage

<!-- xref:usage stats -->
```text
xref stats
```
<!-- /xref -->

## Arguments and options

<!-- xref:options stats -->

<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Stats

Instant overview of stripped xref.stripped (0 symbols, 1,974 .eh_frame functions, 588 panic locations).

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped stats
```

```text output
functions 1974  code 0x177f94 bytes
largest 0xd7740..0xf13ff (0x19cbf bytes)
pointers 1510  imports 80  symbols 0
panic locations 588  source files 143
build-id b92225b515180d48e13b5c4fb66fc1249934e354
toolchain GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0 | rustc version 1.99.1 (58cf8f9c3 2026-10-13) | Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)
```

```stderr
xref: load 828.6µs, total 3.8ms
```
<!-- /xref -->

## Reading the output

- `functions` and `code`: number of functions from `.eh_frame` and the bytes of code they cover.
- `largest`: the biggest function range.
- `pointers`, `imports`, `symbols`: data slots holding code addresses, imported functions, and symbol-table entries (0 when stripped).
- `panic locations`, `source files`: Rust panic `Location` descriptors found and the distinct files they name.

## Limits

- Counts describe what xref can see statically; functions without unwind information are covered by span fallback and may be split or merged.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
