# xref refs

Find every instruction and data slot that names an address or a piece of text.
It is the usual first step on a stripped binary: start from a string you can
see in the program's output, find the code that uses it, then read that code
with [`c`](c.md) or [`asm`](https://github.com/alex09x/xref/blob/main/README.md#command-reference).

## Usage

<!-- xref:usage refs -->
```text
xref refs [OPTIONS] <TARGETS>...
```
<!-- /xref -->

Each target is either an address (`0x…`) or text (anything else). Several
targets are searched in one pass. The binary comes from `-b BIN` or the
`XREF_BIN` environment variable.

## Arguments and options

<!-- xref:options refs -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<TARGETS>...` | Addresses (`0x...`) or texts to search references to. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--back <BACK>` | Also accept references this many bytes before a text (rustc format pieces start with a length byte). | `1` |
| `--inline` | Search for strings built inline from immediate stores (`movabs` / `mov [mem], imm`). |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Find the code that uses a string

ripgrep prints `searches_with_match` in its `--json` statistics. `refs` finds
the string in `.rodata` and every instruction that loads its address:

<!-- xref:run -->
```console
$ xref -b rg refs searches_with_match
```

```text output
text 0x492c1a  "searches_with_match"
0x183676  in 0x1835f0  lea rsi, [0x492c1a]
0x1837d5  in 0x183750  lea rsi, [0x492c1a]
0x183a48  in 0x1838b0  movups xmm0, [0x492c1a]
0x183e4d  in 0x183dd0  lea rsi, [0x492c1a]
0x183f9e  in 0x183f20  lea rsi, [0x492c1a]
5 hits
```

```stderr
xref: load 2.4ms, total 6.9ms
```
<!-- /xref -->

The first line is the string itself (`text ADDRESS "…"`). Each following line
is one reference: the instruction address, the function that contains it
(`in 0x…`, its start address) and the instruction. Five serializer functions use
the key; `0x1835f0` is the one examined on the [`field`](field.md) and
[`c`](c.md) pages. `movups xmm0, [0x492c1a]` in `0x1838b0` copies the bytes
instead of passing a pointer; it is still a reference.

### Search several targets at once

<!-- xref:run -->
```console
$ xref -b rg refs bytes_searched matched_lines
```

```text output
text 0x492c2d  "bytes_searched"
text 0x492c48  "matched_lines"
0x183697  in 0x1835f0  lea rsi, [0x492c2d]
0x1836d1  in 0x1835f0  lea rsi, [0x492c48]
0x1837f4  in 0x183750  lea rsi, [0x492c2d]
0x183836  in 0x183750  lea rsi, [0x492c48]
0x183c23  in 0x1838b0  lea rsi, [0x492c48]
0x183e6c  in 0x183dd0  lea rsi, [0x492c2d]
0x183eaa  in 0x183dd0  lea rsi, [0x492c48]
0x183fbb  in 0x183f20  lea rsi, [0x492c2d]
0x183ff5  in 0x183f20  lea rsi, [0x492c48]
9 hits
```

```stderr
xref: load 2.4ms, total 6.9ms
```
<!-- /xref -->

Hits from all targets are merged and sorted by address. Functions that appear
for both keys (here `0x1835f0`, `0x183750`, `0x183dd0`, `0x183f20`) are the
likely serializers of the structure that holds both fields.

### Find references to an address

An address target lists code that takes that address (`lea`), loads a pointer
slot holding it, or a data slot that stores it:

<!-- xref:run max=12 -->
```console
$ xref -b xref.stripped refs 0x162bb0
```

```text output
0xbfdd1  in 0xbfdb0  lea rax, [0x162bb0]
0xbfebb  in 0xbfe20  lea rax, [0x162bb0]
0xc0489  in 0xbff20  lea rax, [0x162bb0]
0xc0d21  in 0xbff20  lea rax, [0x162bb0]
0xf9b46  in 0xf98f0  lea rax, [0x162bb0]
0xf9c6b  in 0xf98f0  lea rax, [0x162bb0]
0xf9f0b  in 0xf98f0  lea rax, [0x162bb0]
0x124a98  in 0x124050  lea rax, [0x162bb0]
0x136c77  in 0x136240  lea rax, [0x162bb0]
9 hits
```

```stderr
xref: load 605.8µs, total 2.1ms
```
<!-- /xref -->

Direct `call`/`jmp` instructions to a function are not listed here; use
`xref callers ADDRESS` for call sites.

### Find text built from immediate stores

Short strings are often not in `.rodata` at all: the compiler writes their bytes
with `mov` instructions. `--inline` searches for such stores:

<!-- xref:run -->
```console
$ xref -b xref.stripped refs --inline "while ("
```

```text output
0xcfa1b  in 0xc7fc0..0xd0a9d  "while (" (7/7 bytes at 0xcfa1b)
1 hits
```

```stderr
xref: load 660.8µs, total 2.0ms
```
<!-- /xref -->

`(7/7 bytes at 0xcfa1b)` says all seven bytes were found in stores starting at
that instruction. `xref istr TEXT` is the same search.

### A string that occurs many times

<!-- xref:run max=16 -->
```console
$ xref -b xref.stripped refs "goto L_"
```

```text output
text 0x10ecc  "goto L_"
text 0x12045  "goto L_"
text 0x12419  "goto L_"
text 0x125fe  "goto L_"
text 0x150e7  "goto L_"
0xba3e7  in 0xb43a0  lea rsi, [0x12044]
0xc7e04  in 0xc7d60  lea rcx, [0x150e7]
0xcc270  in 0xc7fc0  lea rsi, [0x12044]
0xcd278  in 0xc7fc0  lea rsi, [0x12044]
0xcd908  in 0xc7fc0  lea r12, [0x12044]
0xcdb5e  in 0xc7fc0  lea rsi, [0x12044]
0xcdba0  in 0xc7fc0  lea rsi, [0x12044]
0xcdd07  in 0xc7fc0  lea rsi, [0x12044]
0xce17c  in 0xc7fc0  lea rsi, [0x12044]
0xce445  in 0xc7fc0  lea rsi, [0x12044]
0xce5fc  in 0xc7fc0  lea rsi, [0x12044]
```
*Output cut here: lines 1–16 of 22 shown.*

```stderr
xref: load 502.6µs, total 2.5ms
```
<!-- /xref -->

Every copy of the text is listed first, then the references to any of them.
A reference can point one byte before a copy (`[0x12044]` for the text at
`0x12045`): Rust format strings start with a length byte, and `--back`
(default `1`) accepts references up to that many bytes before the text. Use
`--back 0` for exact matches only.

## Reading the output

- `text ADDR "…"`: one occurrence of the searched text in the image.
- `INSN_ADDR  in FN_START  INSTRUCTION`: an instruction that names the target.
  `FN_START` is the start of the containing function from `.eh_frame`.
- `N hits`: number of reference lines.
- stderr `xref: load …, total …`: time to map the image and run the query.

## Limits

- Only references whose address is computed directly (`lea`, RIP-relative
  operands, absolute pointer slots) are found. Addresses built arithmetically at
  run time are not.
- Text search is a byte search: the same bytes inside a longer string match too.
- `refs` does not decode which argument the address is passed in; for that use
  `xref args FUNCTION` on the callee.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
