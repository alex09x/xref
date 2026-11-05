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
xref: load 2.0ms, total 6.3ms
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
xref: load 2.1ms, total 6.9ms
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
xref: load 559.7µs, total 2.1ms
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
xref: load 602.6µs, total 2.1ms
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
0xb6aa4  in 0xb43a0  lea rsi, [0x125f5]  ; likely fmt template 0x125f5, piece 1
0xb868d  in 0xb43a0  lea rsi, [0x10ec6]  ; likely fmt template 0x10ec6, piece 1
0xb8d2e  in 0xb43a0  lea rsi, [0x12414]  ; likely fmt template 0x12414, piece 0
0xba3e7  in 0xb43a0  lea rsi, [0x12044]  ; likely fmt template 0x12044, piece 0
0xba599  in 0xb43a0  lea rsi, [0x125f5]  ; likely fmt template 0x125f5, piece 1
0xc7e04  in 0xc7d60  lea rcx, [0x150e7]
0xcc270  in 0xc7fc0  lea rsi, [0x12044]  ; likely fmt template 0x12044, piece 0
0xcc3a6  in 0xc7fc0  lea rsi, [0x125f5]  ; likely fmt template 0x125f5, piece 1
0xcd278  in 0xc7fc0  lea rsi, [0x12044]  ; likely fmt template 0x12044, piece 0
0xcd908  in 0xc7fc0  lea r12, [0x12044]  ; likely fmt template 0x12044, piece 0
0xcdb5e  in 0xc7fc0  lea rsi, [0x12044]  ; likely fmt template 0x12044, piece 0
```
*Output cut here: lines 1–16 of 27 shown.*

```stderr
xref: load 497.2µs, total 3.1ms
```
<!-- /xref -->

Every copy of the text is listed first, then the references to any of them.
A reference can point one byte before a copy (`[0x12044]` for the text at
`0x12045`): that byte is the length prefix of a `format!` template piece, and
`--back` (default `1`) accepts direct references up to that many bytes before
the text; `--back 0` keeps only direct references to the text itself. It does
not turn off the `format!` template lookup described next.

### A later piece of a `format!` message

Recent rustc (the template representation of `core::fmt`; `xref.stripped`
is built with rustc 1.99) compiles a `format!` string with arguments into one
byte template: each literal piece is prefixed by its length, each `{}` is a
placeholder byte (`0xC0` and up), and a `0` ends it. Code loads only the start
of the template, so the text of a later piece, or a piece after a
placeholder, is not referenced directly. `refs` looks for code that loads a
template start up to 4 KiB before the text, parses the template to its end
and requires at least one placeholder; a match is noted as
`; likely fmt template START, piece N`. Here every template begins with a
placeholder, so the text starts a few bytes after the address the code loads:
two when the placeholder has no optional fields (`0x119c1` → `0x119c3`), more
when it carries flags, width or precision fields (`0x13171` → `0x13177`):

<!-- xref:run max=14 -->
```console
$ xref -b xref.stripped refs "overflow("
```

```text output
text 0x11690  "overflow("
text 0x119c3  "overflow("
text 0x12052  "overflow("
text 0x12771  "overflow("
text 0x13177  "overflow("
text 0x135fd  "overflow("
text 0x1464c  "overflow("
0xbf388  in 0xbf310  lea rsi, [0x119c1]  ; likely fmt template 0x119c1, piece 0
0xbf3c5  in 0xbf310  lea rsi, [0x12050]  ; likely fmt template 0x12050, piece 0
0xbf417  in 0xbf310  lea rsi, [0x13171]  ; likely fmt template 0x13171, piece 0
0xbf4a2  in 0xbf310  lea rsi, [0x135f7]  ; likely fmt template 0x135f7, piece 0
0xbf511  in 0xbf310  lea rsi, [0x1168a]  ; likely fmt template 0x1168a, piece 0
0xbf57d  in 0xbf310  lea rsi, [0x1276b]  ; likely fmt template 0x1276b, piece 0
0xfa3ca  in 0xfa330  lea rdi, [0x1464c]
```
*Output cut here: lines 1–14 of 15 shown.*

```stderr
xref: load 442.7µs, total 3.2ms
```
<!-- /xref -->

The template search does not depend on `--back`: the `lea` lines without a
note are direct references, the others were found through their template.

## Reading the output

- `text ADDR "…"`: one occurrence of the searched text in the image.
- `INSN_ADDR  in FN_START  INSTRUCTION`: an instruction that names the target.
  `FN_START` is the start of the containing function from `.eh_frame`.
- `; likely fmt template START, piece N`: the instruction loads the start of
  a `format!` byte template whose piece `N` (from 0) contains the text. The
  template was parsed completely, but a byte sequence can follow the grammar
  by chance, hence "likely".
- `; likely fmt pieces array START, piece N`: older rustc output, a
  relocated array of `(pointer, length)` pairs, one of which points at the
  text; the instruction loads an element of that array.
- `N hits`: number of reference lines.
- stderr `xref: load …, total …`: time to map the image and run the query.

## Limits

- Only references whose address is computed directly (`lea`, RIP-relative
  operands, absolute pointer slots) are found. Addresses built arithmetically at
  run time are not.
- Text search is a byte search: the same bytes inside a longer string match too.
- Template lookup runs only for up to 64 copies of a text and looks back at
  most 4 KiB; a template that starts farther away is not found.
- `refs` does not decode which argument the address is passed in; for that use
  `xref args FUNCTION` on the callee.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
