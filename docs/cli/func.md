# xref func

The function (exact `.eh_frame` range) containing each address.

Summarizes .eh_frame function boundaries, code bytes, relocated pointers, imports, symbol count, and Rust panic locations without writing an index.

## Usage

<!-- xref:usage func -->
```text
xref func <ADDRS>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options func -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDRS>...` | Addresses to look up (`0x...` hex or decimal). |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Func 0xc7e18 0x9f10f 0xd567e

Maps arbitrary interior instruction addresses back to their exact .eh_frame function ranges.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped func 0xc7e18 0x9f10f 0xd567e
```

```text output
0xc7e18  in 0xc7d60..0xc7fbf  size 0x25f  offset 0xb8
0x9f10f  in 0x9ef60..0x9f518  size 0x5b8  offset 0x1af
0xd567e  in 0xd5490..0xd57b1  size 0x321  offset 0x1ee
```

```stderr
xref: load 1.3ms, total 1.3ms
```
<!-- /xref -->

## Reading the output

- One line per address: the address, the function range that contains it, the function size and the offset of the address inside it.

## Limits

- Ranges come from `.eh_frame`; addresses outside every unwind range (padding, data) are reported as not inside a function.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
