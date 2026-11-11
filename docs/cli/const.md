# xref const

A constant by value: its aligned copies in data with the instructions loading each, and immediates with the same bits.

Compilers keep floating-point constants (and wide integers) in read-only data and load them RIP-relative (`movsd xmm0, [0x454ec8]`). `xref const` takes the value instead of its address: it finds every copy of its bytes, keeps the copies aligned to the value's width that lie outside function code, and lists the instructions that name each copy. Immediates carrying the same bit pattern (`movabs rax, 0x3ff028f5c28f5c29`, `mov eax, 0x3f800000`) are listed too.

## Usage

<!-- xref:usage const -->
```text
xref const [OPTIONS] <--f64 <F64>|--f32 <F32>|--u64 <U64>|--u32 <U32>>
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
xref: load 3.4ms, total 13.3ms
```
<!-- /xref -->

## Reading the output

- The first line is the value and its bit pattern.
- `data ADDR  N users` is one copy of the value in data, followed by the instructions naming it (address, containing function, instruction). `refs ADDR` lists the same users for one copy.
- `imm  N users` lists instructions whose immediate operand has the same bits. For a small integer (`--u64 1`) this is every `1` in the program; use [`imm`](imm.md) with `--cmp` / `--store` to narrow it.
- `N data copies without RIP-relative users` counts aligned copies no instruction names directly: unrelated bytes that happen to match, or a value reached through a pointer or as the upper half of a 16-byte vector constant.

## Limits

- Only aligned copies outside function code count; a value packed into a 16-byte vector constant is found only when the instruction names its own address.
- A `--f64` value is matched bit for bit: `0.1` finds the double nearest to 0.1, not values computed at run time.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.5.0 (branch const-value on main 42c4fed) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
