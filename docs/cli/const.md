# xref const

A constant by value: its aligned copies in data with the instructions loading each, and immediates with the same bits.

Compilers keep floating-point constants (and wide integers) in read-only data and load them RIP-relative (`movsd xmm0, [0x454ec8]`). `xref const` takes the value instead of its address: it finds every copy of its bytes, keeps the copies aligned to the value's width that lie outside function code, and lists the instructions that name each copy. Immediates carrying the same bit pattern (`movabs rax, 0x3ff028f5c28f5c29`, `mov eax, 0x3f800000`) are listed too.

## Usage

<!-- xref:usage const -->
```text
xref const [OPTIONS] <--f64 <F64>|--f32 <F32>|--u64 <U64>|--u32 <U32>|--bytes <BYTES>>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options const -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--f64 <F64>` | A double, e.g. `1.01` or `-0.5`. |  |
| `--f32 <F32>` | A float, e.g. `0.25`. |  |
| `--u64 <U64>` | A 64-bit integer (`0x...` hex or decimal). |  |
| `--u32 <U32>` | A 32-bit integer (`0x...` hex or decimal). |  |
| `--bytes <BYTES>` | A byte string in memory order (`0x0011..`, `00 11 ..`, `00:11:..`), e.g. a 20-byte address; also lists the 16/8/4-byte pieces code compares it in and the functions using them. |  |
| `--limit <LIMIT>` | Users listed per copy (and for immediates). | `100` |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### --f64 1e9

<!-- xref:run max=40 -->
```console
$ xref -b rg const --f64 1e9 --limit 3
```

```text output
f64 1000000000 = 0x41cdcd6500000000
data 0x492fc0  5 users
  0x1949ee  in 0x193790  divsd xmm0, [0x492fc0]
  0x194d37  in 0x193790  movsd xmm4, [0x492fc0]
  0x196325  in 0x1957c0  divsd xmm0, [0x492fc0]
  ... 2 more (raise --limit)
5 hits
```

```stderr
xref: load 4.8ms, total 29.6ms
```
<!-- /xref -->

## Reading the output

- The first line is the value and its bit pattern.
- When more than one copy has users, the second line names them all with their user counts (`3 data copies with users: 0x402a88 (12), 0x401f40 (3), 0x401230 (1)`), and the copies follow most used first. A value often sits in data several times, each copy loaded by different code, so check the whole list before concluding a use is missing.
- `data ADDR  N users` is one copy of the value in data, followed by the instructions naming it (address, containing function, instruction). `refs ADDR` lists the same users for one copy.
- `imm  N users` lists instructions whose immediate operand has the same bits. For a small integer (`--u64 1`) this is every `1` in the program; use [`imm`](imm.md) with `--cmp` / `--store` to narrow it.
- `N data copies without RIP-relative users` counts aligned copies no instruction names directly: unrelated bytes that happen to match, or a value reached through a pointer or as the upper half of a 16-byte vector constant.

### Byte strings

`--bytes HEX` takes an arbitrary byte string in memory order (`0x0011…`, `00 11 …` or `00:11:…`, up to 256 bytes), such as a 20-byte account address or a hash. Code rarely loads such a value whole. A 20-byte compare is typically a 16-byte `pcmpeqb xmm0, [const]` plus the last 4 bytes in one of two forms. One is `cmp dword ptr [rdi+0x10], imm32`. The other is `movd xmm1, [rdi+0x10]` followed by `pcmpeqb xmm1, [const2]`, where `const2` holds the 4 bytes padded with zeros to 16. A third pattern is two loads at +0 and +0x10 from one 20-byte copy. So the output covers both:

```text
bytes 20 = 0102030405060708090a0b0c0d0e0f1011121314
full  data 0x402a80  2 users
  0x401230  in 0x401200  movdqu xmm1, [0x402a80]
  0x401238  in 0x401200  mov eax, [0x402a90]  (+0x10)
piece 0..16  data 0x402b00  1 users
  0x401300  in 0x4012f0  pcmpeqb xmm0, [0x402b00]
piece 16..20  imm 0x14131211  1 users
  0x401308  in 0x4012f0  cmp dword ptr [rdi+0x10], 0x14131211
by function:
  0x401200  full
  0x4012f0  piece 0..16, piece 16..20
4 hits
```

- `full  data ADDR` is a copy of the whole string, with every instruction naming any byte of it; `(+0x10)` marks a load from inside the copy.
- `piece A..B` are the parts a compare is split into: 16-byte chunks, then 8 and 4 bytes of the rest (20 = 16 + 4); a remainder of 1–3 bytes is taken as the overlapping last 4 bytes, since shorter pieces would match all over the data; and the overlapping last 16 bytes (`piece 4..20`) that some compilers load instead. A piece is looked up as its own data copy (aligned to its width, up to 16) and, for 4 and 8 bytes, as an immediate. Copies lying inside a whole copy are not repeated.
- `by function` names the functions using the value and which parts each uses. A function using every piece is usually the comparison.

## Limits

- Only aligned copies outside function code count; a value packed into a 16-byte vector constant is found only when the instruction names its own address.
- A `--f64` value is matched bit for bit: `0.1` finds the double nearest to 0.1, not values computed at run time.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
