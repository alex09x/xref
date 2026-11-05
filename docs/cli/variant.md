# xref variant

Jump-table arms of the function containing an address for enum variant indices, with the texts they name.

Resolves relative jump tables into variant arm ranges, string literals per arm, reverse instruction-to-arm ownership, and constant error returns.

## Usage

<!-- xref:usage variant -->
```text
xref variant <ADDR> <INDICES>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options variant -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` |  |  |
| `<INDICES>...` |  |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Variant 0xc7fc0 2

Jump-table arms for variant index 2 inside 0xc7fc0 and the string literals referenced in each arm.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped variant 0xc7fc0 2
```

```text output
table 0xc030  variant 2 (0x2)  arm 0xc80b0..0xc80f0
table 0xc080  variant 2 (0x2)  arm 0xcbf99..0xcc060
table 0xc06c  variant 2 (0x2)  arm 0xce1f1..0xd0a9d  "goto L_"  "if ("  "goto L_"  "if ("  "if ("  "goto L_"  "if ("  "L_"  "goto L_"  "goto L_"  "L_"  "start of range should be a character boundaryInvalid ELF section"  "123456789dqwz"  "while ("  "} while ("  "  "  "  "  "} while ("  "start of range should be a character boundaryInvalid ELF section"  "start of range should be a character boundaryInvalid ELF section"
table 0xc058  variant 2 (0x2)  arm 0xcd528..0xcd52c
table 0xc044  variant 2 (0x2)  arm 0xcdf32..0xce1c9  "goto L_"
```

```stderr
xref: load 443.5µs, total 877.8µs
```
<!-- /xref -->

## Reading the output

- One line per jump table of the function: the table, the variant index, the arm range, and the string literals the arm references (in code order).

## Limits

- Strings are listed as referenced bytes from `.rodata`; long previews can run into neighbouring data.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2; `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
