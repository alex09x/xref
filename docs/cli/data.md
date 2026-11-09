# xref data

Read typed values at a virtual address of the binary: the address is mapped
through the load segments (ELF `PT_LOAD`, Mach-O segments) and each element is
printed with its address. Use it when pseudo-C or assembly loads from a
constant address (a table indexed by some value, a string, a constant) and you
want the values without writing an ELF reader.

## Usage

<!-- xref:usage data -->
```text
xref data [OPTIONS] --as <AS_TYPE> <VA>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options data -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<VA>` | Virtual address to read from (`0x...` hex or decimal). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--as <AS_TYPE>` | Data type to read (f64, f32, u64, u32, u16, u8, i64, i32, i16, i8, bytes, str) [possible values: f64, f32, u64, u32, u16, u8, i64, i32, i16, i8, bytes, str]. |  |
| `--count <COUNT>` | Number of elements to read (byte count for bytes; default 1, or 64 for bytes). |  |
| `--max-len <MAX_LEN>` | Maximum string length to read up to the first NUL (default 256). | `256` |
<!-- /xref -->

## Examples

### A string in read-only data

`0x492c0b` is the string ripgrep's statistics serializer passes (see
[`card`](card.md)). The serializer slices it by length, so the bytes after
the first key belong to the next keys:

<!-- xref:run -->
```console
$ xref -b rg data 0x492c0b --as str
```

```text output
0x492c0b  str  "elapsedsearchessearches_with_matchbytes_searchedbytes_printedmatched_linesmatchesbeginendmatchcontextstartnanoshumanPoisonError\n"
```

```stderr
xref: load 3.3ms, total 3.3ms
```
<!-- /xref -->

### The same bytes as a hex dump

<!-- xref:run -->
```console
$ xref -b rg data 0x492c0b --as bytes --count 32
```

```text output
0x492c0b  65 6c 61 70 73 65 64 73 65 61 72 63 68 65 73 73
0x492c1b  65 61 72 63 68 65 73 5f 77 69 74 68 5f 6d 61 74
```

```stderr
xref: load 2.9ms, total 2.9ms
```
<!-- /xref -->

### Zero-initialised data

`0x84a560` is past the file-backed part of ripgrep's writable segment, so
the values are zero in the file and marked `(bss)`:

<!-- xref:run -->
```console
$ xref -b rg data 0x84a560 --as u64 --count 2
```

```text output
0x84a560  u64  0  (bss)
0x84a568  u64  0  (bss)
```

```stderr
xref: load 3.7ms, total 3.7ms
```
<!-- /xref -->

### An address outside the binary

<!-- xref:run -->
```console
$ xref -b rg data 0x900000 --as f64
```

*(no stdout)*

Exit status 1.

```stderr
xref: VA 0x900000 is outside all segments; nearest segment is 0x785af0..0x896148 (permissions: ?w- (read bit not recorded))
```
<!-- /xref -->

## Reading the output

- One line per element: address, type, value. `f64` and `f32` use the
  shortest form that reads back the same value (`1.0`, `1e19`).
- `str` reads up to the first NUL byte and prints the text escaped. If no NUL
  is found within `--max-len` bytes, the line says the text was capped.
- `bytes` prints 16 bytes per line with the address of the line.
- `(bss)` marks values past the file-backed part of a segment. The file holds
  no bytes for them, so they read as zero; at run time the program may have
  changed them.
- A range that runs past the end of its segment is cut there, with a line
  saying so.
- An address outside every segment is an error that names the nearest segment.
  The read permission is printed as `?` because xref does not record it.

## Limits

- Values are what the file holds. Data the dynamic loader relocates at start
  (pointers in `.data.rel.ro`, `.got`) reads as its addend or zero here; use
  [`refs`](refs.md) to follow such pointers, or
  [`live memscan`](live-memscan.md) on a running process for run-time values.
- `--count` is limited to 65,536 elements, or 1 MiB for `bytes`.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
