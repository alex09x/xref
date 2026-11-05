# xref card

A one-screen summary of a function: which argument registers and stack slots it
reads, its return registers, the fields it stores to (grouped by base), every
call with its decoded arguments, indirect calls, panic paths and exits. Use it
to decide whether a function is worth reading in full with [`c`](c.md).

## Usage

<!-- xref:usage card -->
```text
xref card [OPTIONS] <FN>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options card -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<FN>` | Target function address or symbol name. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--json` | Emit the function card as JSON. |  |
<!-- /xref -->

## Examples

### Summarize a function

ripgrep's statistics serializer (see [`field`](field.md)):

<!-- xref:run max=40 -->
```console
$ xref -b rg card 0x1835f0
```

```text output
function 0x1835f0..0x18374c
inputs:
  registers: rdi, rsi
  stack: none
return registers: rax
stores:
  arg1:
    +0x18: 8
    +0x20: 1
  stack:
    +0x0: 8
    +0x8: 1
callees:
  0x183644: 0x15bf60(rdi=rsp, rsi=0x492c0b ("elapsedsearchessearches_with_matchbytes_searchedbytes_printedmat"), rdx=7, rcx=rcx (dynamic), stack0=rsi (dynamic), stack1=1)
  0x183664: 0x158e60(rdi=rsp, rsi=0x492c12 ("searchessearches_with_matchbytes_searchedbytes_printedmatched_li"), rdx=8, rcx=rbx, stack0=rsi (dynamic), stack1=1)
  0x183685: 0x158e60(rdi=rsp, rsi=0x492c1a ("searches_with_matchbytes_searchedbytes_printedmatched_linesmatch"), rdx=0x13, rcx=rcx (dynamic), stack0=rsi (dynamic), stack1=1)
  0x1836a6: 0x158e60(rdi=rsp, rsi=0x492c2d ("bytes_searchedbytes_printedmatched_linesmatchesbeginendmatchcont"), rdx=0xe, rcx=rcx (dynamic), stack0=rsi (dynamic), stack1=1)
  0x1836c3: 0x158e60(rdi=rsp, rsi=0x492c3b ("bytes_printedmatched_linesmatchesbeginendmatchcontextstartnanosh"), rdx=0xd, rcx=rcx (dynamic), stack0=rsi (dynamic), stack1=1)
  0x1836e0: 0x158e60(rdi=rsp, rsi=0x492c48 ("matched_linesmatchesbeginendmatchcontextstartnanoshumanPoisonErr"), rdx=0xd, rcx=rcx (dynamic), stack0=rsi (dynamic), stack1=1)
  0x183700: 0x158e60(rdi=rsp, rsi=0x492c55 ("matchesbeginendmatchcontextstartnanoshumanPoisonError"), rdx=7, rcx=rbx, stack0=rsi (dynamic), stack1=1)
  0x183712: 0x187760(rdi=u64 [rsp], rsi=u32 [rsp+0x8], stack0=rsi (dynamic), stack1=1)
  0x18373b: 0x80aa0(rdi=rdi (dynamic), rsi=rax, rdx=1, rcx=1, r8=1, stack0=rsi (dynamic), stack1=1)
indirect calls:
  none
panics:
  none
exits:
  0x183720: ret (rax)
```

```stderr
xref: load 2.5ms, total 5.0ms
```
<!-- /xref -->

How to read it:

- `inputs`: argument registers and stack arguments the function reads before
  writing them.
- `stores`: memory written, grouped by base (`arg1` is the second argument,
  `rsi`); each line is an offset and the store widths in bytes.
- `callees`: each call site, its target and the arguments xref could decode.
  A string argument shows the address and a preview of the bytes there; the
  length argument (`rdx=8` for `searches`) says how many of them belong to the
  string, the rest of the preview is whatever follows in `.rodata`.
  `(dynamic)` marks values computed at run time.
- `panics` and `exits`: panic call sites and return instructions.

### Machine-readable

<!-- xref:run max=30 -->
```console
$ xref -b rg card 0x1835f0 --json
```

```json output
{
  "function": {
    "start": 1586672,
    "end": 1587020,
    "name": null
  },
  "inputs": {
    "registers": [
      "rdi",
      "rsi"
    ],
    "stack_args": []
  },
  "return_registers": [
    "rax"
  ],
  "stores": {
    "arg1": [
      {
        "offset": 24,
        "widths": [
          8
        ]
      },
      {
        "offset": 32,
        "widths": [
          1
        ]
      }
```
*Output cut here: lines 1–30 of 177 shown.*

```stderr
xref: load 2.5ms, total 5.2ms
```
<!-- /xref -->

## Limits

- Argument decoding follows the x86-64 System V convention; values passed
  through memory or computed in callers show as `(dynamic)`.
- `stack0`, `stack1` are the first stack-passed argument slots at the call site
  as the decoder sees them; for calls with six or fewer register arguments they
  may hold unrelated values.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2; `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
