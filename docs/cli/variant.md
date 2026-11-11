# xref variant

Jump-table arms of the function containing an address for enum variant indices, with the texts they name.

Resolves relative jump tables into variant arm ranges, string literals per arm, reverse instruction-to-arm ownership, and constant error returns.

## Usage

<!-- xref:usage variant -->
```text
xref variant [OPTIONS] <ADDR> [INDICES]...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options variant -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | An address inside the function. |  |
| `[INDICES]...` | Enum variant indices or inclusive ranges (`7 0x2c 218-222`); every index when omitted. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--table <TABLE>` | Only the jump table at this address (`table` in the output). |  |
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
xref: load 502.3µs, total 943.9µs
```
<!-- /xref -->

## Reading the output

- One line per jump table and index: the table, the variant index, the arm range, what the
  arm does, and the string literals it references (in code order).
- What the arm does: `calls A, B x2, tail C` lists the calls and tail jumps inside the arm in
  code order (repeats collapsed); an arm without calls shows the jump it takes into shared code
  (`-> 0x...`). For a dispatcher this is the case -> handler table.
- Without indices every index of every table is listed; `218-222` is an inclusive range;
  `--table ADDR` keeps one table.
- A string literal passed as `(ptr, len)` is cut to its length when the length register is set
  before the next call (`lea rsi, [text]` ... `mov edx, 1`), so packed Rust literals show as
  `"e"` rather than running into their neighbours.

## Limits

- Strings without a recoverable length are listed as referenced bytes from `.rodata`; long
  previews can run into neighbouring data.
- An arm ends at the next higher arm of the table; the last arm runs to the function end, so its
  calls can include code shared after the switch.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
