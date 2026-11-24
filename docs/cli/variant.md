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
| `--names-from <NAMES_FROM>` | Name each index after a function writing the enum's variant names (its `Display`, `Serialize` or `Debug`), matched through the tag value when both tag loads are found. |  |
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
table 0xc030  variant 2 (0x2)  arm 0xc80b0..0xc80f0  -> 0xc8140
table 0xc080  variant 2 (0x2)  arm 0xcbf99..0xcc060  calls 0x1b7a60
table 0xc06c  variant 2 (0x2)  arm 0xce1f1..0xd0a9d  calls 0x127630 x2, 0x1b7a60, 0x127630 x2, 0x1b7a60, 0x127630, 0x1b7a60, 0x127630 x2, 0x1b7a60, +71 more  "goto L_"  "if ("  "goto L_"  "if ("  "if ("  "goto L_"  "if ("  "L_"  "goto L_"  "goto L_"  "L_"  "start of range should be a character boundaryInvalid ELF section indexUnsupported ELF sh_in"  "123456789dqwz"  "while ("  "} while ("  "  "  "  "  "} while ("  "start of range should be a character boundaryInvalid ELF section indexUnsupported ELF sh_in"  "start of range should be a character boundaryInvalid ELF section indexUnsupported ELF sh_in"
table 0xc058  variant 2 (0x2)  arm 0xcd528..0xcd540
table 0xc044  variant 2 (0x2)  arm 0xcdf32..0xce1f1  calls 0x127a00 x2, 0x127630  "goto L_"
```

```stderr
xref: load 765.3µs, total 1.4ms
```
<!-- /xref -->

## Reading the output

- One line per jump table and index: the table, the variant index, the arm range, what the
  arm does, and the string literals it references (in code order).
- What the arm does: `calls A, B x2, tail C` lists the calls and tail jumps inside the arm in
  code order (repeats collapsed, at most 8 targets, then `+N more`); an arm without calls shows the jump it takes into shared code
  (`-> 0x...`). For a dispatcher this is the case -> handler table.
- Without indices every index of every table is listed; `218-222` is an inclusive range;
  `--table ADDR` keeps one table.
- A string literal passed as `(ptr, len)` is cut to its length when the length register is set
  before the next call (`lea rsi, [text]` ... `mov edx, 1`), so packed Rust literals show as
  `"e"` rather than running into their neighbours.

### Names from another function

A dispatcher's `match` says which handler each variant gets, but not the variant's name. The
enum's `Display`, `Serialize` or `Debug` writes the names; `--names-from FN` takes them from
FN's largest jump table and adds them to the lines:

```text
table 0x402a80  names from 0x401230 table 0x402c00, by tag value: here u64 [r15+0x0] = index + 0x88, dataful index 20, there u64 [rdi+0x0] = index + 0x88, dataful index 20
table 0x402a80  variant 0 (0x0)  arm 0x401500..0x401513  name "Noop" / "noop"  calls 0x403000
table 0x402a80  variant 1 (0x1)  arm 0x401513..0x40152d  name "Transfer" / "transfer"  calls 0x403100
```

- The two tables may number the variants differently: a niche-encoded tag is `index + bias`,
  and the variant holding the payload (the dataful index) has no tag value of its own. When the
  tag load of both dispatches is found, an index is carried over through its tag value, and the
  header line shows both tags. Otherwise indices are matched one to one, and only when both
  tables have as many arms.
- An arm's names are its `(ptr, len)` identifier literals, in argument registers or stored as
  pairs on the stack; up to two are shown (the variant name and its serde rename). A literal
  written by most arms (the enum's name, a `"type"` key) names no single variant and is left out.

## Limits

- Strings without a recoverable length are listed as referenced bytes from `.rodata`; long
  previews can run into neighbouring data.
- A table ends at its range check (`cmp idx, 4; ja default` gives 5 variants) and never runs
  into the next address the function references, such as an adjacent table; without either it
  is read while its entries point into the function.
- An arm ends at the next higher arm of any table in the function (so an arm holding a nested
  `match` stops where the inner arms start); the last arm runs to the function end, so its
  calls can include code shared after the switch.
- A table dispatched from several places is listed once.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
