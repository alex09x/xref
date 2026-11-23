# xref disp

Instructions reading or writing struct fields: non-stack memory operands with these displacements.

Locates loads, stores, and lea field-pointer computations at exact byte displacements, optionally intersecting offsets or filtering by SIB scale/stride.

## Usage

<!-- xref:usage disp -->
```text
xref disp [OPTIONS] <VALUES>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options disp -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<VALUES>...` | Field displacements (`0x...` hex or decimal). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--write` | Only instructions writing the memory operand. |  |
| `--lea` | Only `lea` instructions taking the field's address. |  |
| `--all` | Functions accessing all of the given displacements (an intersection), with per-function counts. |  |
| `--stride <STRIDE>` | Only accesses whose base or index register was computed with this array element stride. |  |
| `--stack` | Include stack displacements and fields relative to explicitly address-taken stack buffers. |  |
| `--in <WITHIN>` | Only inside the function containing this address. |  |
| `--who-serializes` | The key each displacement is serialized under: calls passing a `(ptr, len)` key literal together with the field, or "not serialized". |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Disp 0x20 --in 0x9ef60

Non-stack memory loads/stores at offset +0x20 inside function 0x9ef60..0x9f518.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped disp 0x20 --in 0x9ef60
```

```text output
0x9efb8  in 0x9ef60  mov r15, [rsi+0x20]
1 hits
```

```stderr
xref: load 2.0ms, total 4.4ms
```
<!-- /xref -->

### Disp 0x18 --lea --in 0x65e30

Only lea instructions taking a +0x18 field address (--lea), annotating the receiving callee (; -> 0x1610a0).

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped disp 0x18 --lea --in 0x65e30
```

```text output
0x65e84  in 0x65e30  lea rcx, [r12+0x18]
0x65e9d  in 0x65e30  lea rcx, [rcx+0x18]  ; -> 0x1610a0
2 hits
```

```stderr
xref: load 1.1ms, total 3.3ms
```
<!-- /xref -->

### Disp 0x20 --stride 0x8 --in 0x6f910

Only +0x20 accesses whose base/index register uses array stride 0x8 (--stride 0x8).

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped disp 0x20 --stride 0x8 --in 0x6f910
```

```text output
0x6f9e8  in 0x6f910  mov r12, [rdi+r15*8+0x20]
0x6f9ed  in 0x6f910  mov r9, [rdi+r10*8+0x20]
0x6f9f5  in 0x6f910  mov r13, [rdi+rax*8+0x20]
0x6fa00  in 0x6f910  cmp [rdi+rbx*8+0x20], r13
0x6fa13  in 0x6f910  lea rbx, [rdi+rbp*8+0x20]
0x6fa1c  in 0x6f910  lea r10, [rdi+rax*8+0x20]
0x6fa21  in 0x6f910  mov rax, [rdi+rax*8+0x20]
0x6fa2a  in 0x6f910  cmp [rdi+rbp*8+0x20], rax
0x6fa8b  in 0x6f910  mov rcx, [rdx+r11*8+0x20]
0x6fac6  in 0x6f910  lea r11, [rdx+r11*8+0x20]
10 hits
```

```stderr
xref: load 906.8µs, total 4.1ms
```
<!-- /xref -->

### Disp 0x8 0x10 0x20 0x28 0x30 --all

Functions accessing every listed field offset (intersection via --all) with per-offset hit counts.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped disp 0x8 0x10 0x20 0x28 0x30 --all
```

```text output
0x5bfb0..0x5c187  24 hits (0x8: 9, 0x10: 8, 0x20: 3, 0x28: 1, 0x30: 3)
0x66fe0..0x6711d  15 hits (0x8: 6, 0x10: 2, 0x20: 4, 0x28: 1, 0x30: 2)
0x67120..0x67327  19 hits (0x8: 8, 0x10: 4, 0x20: 4, 0x28: 1, 0x30: 2)
0x67540..0x679c2  35 hits (0x8: 13, 0x10: 6, 0x20: 9, 0x28: 5, 0x30: 2)
0x682b0..0x6844d  10 hits (0x8: 5, 0x10: 2, 0x20: 1, 0x28: 1, 0x30: 1)
0x6a9b0..0x6ae56  25 hits (0x8: 13, 0x10: 7, 0x20: 2, 0x28: 2, 0x30: 1)
0x6ef50..0x6f42a  32 hits (0x8: 17, 0x10: 3, 0x20: 5, 0x28: 2, 0x30: 5)
0x6f430..0x6f90a  32 hits (0x8: 17, 0x10: 3, 0x20: 5, 0x28: 2, 0x30: 5)
0x6f910..0x6fbd4  25 hits (0x8: 3, 0x10: 3, 0x20: 13, 0x28: 3, 0x30: 3)
0x70eb0..0x70fc8  17 hits (0x8: 2, 0x10: 5, 0x20: 5, 0x28: 4, 0x30: 1)
0x79240..0x79f3c  68 hits (0x8: 33, 0x10: 9, 0x20: 12, 0x28: 6, 0x30: 8)
0x84ef0..0x85916  56 hits (0x8: 30, 0x10: 12, 0x20: 8, 0x28: 4, 0x30: 2)
0x85920..0x8633f  30 hits (0x8: 12, 0x10: 6, 0x20: 4, 0x28: 4, 0x30: 4)
0x8a340..0x8c7a2  73 hits (0x8: 26, 0x10: 19, 0x20: 11, 0x28: 9, 0x30: 8)
0x8c7b0..0x8d952  35 hits (0x8: 12, 0x10: 14, 0x20: 5, 0x28: 3, 0x30: 1)
0x8ea10..0x8f64b  45 hits (0x8: 15, 0x10: 15, 0x20: 9, 0x28: 4, 0x30: 2)
0x8f650..0x8ff64  32 hits (0x8: 12, 0x10: 9, 0x20: 6, 0x28: 2, 0x30: 3)
0x8ff70..0x91c10  78 hits (0x8: 31, 0x10: 22, 0x20: 8, 0x28: 10, 0x30: 7)
0x91c10..0x92fa2  28 hits (0x8: 10, 0x10: 11, 0x20: 4, 0x28: 2, 0x30: 1)
0x951c0..0x95300  14 hits (0x8: 5, 0x10: 3, 0x20: 2, 0x28: 2, 0x30: 2)
0x9f520..0xa2196  73 hits (0x8: 21, 0x10: 23, 0x20: 20, 0x28: 4, 0x30: 5)
0xa74a0..0xa7e47  30 hits (0x8: 6, 0x10: 10, 0x20: 7, 0x28: 4, 0x30: 3)
0xa84b0..0xa87e5  17 hits (0x8: 4, 0x10: 8, 0x20: 1, 0x28: 3, 0x30: 1)
0xa87f0..0xa8b3b  19 hits (0x8: 4, 0x10: 4, 0x20: 5, 0x28: 5, 0x30: 1)
0xadd10..0xb2c28  101 hits (0x8: 25, 0x10: 46, 0x20: 15, 0x28: 6, 0x30: 9)
0xb43a0..0xbb5da  358 hits (0x8: 150, 0x10: 131, 0x20: 25, 0x28: 25, 0x30: 27)
0xbb970..0xbde39  88 hits (0x8: 32, 0x10: 38, 0x20: 9, 0x28: 7, 0x30: 2)
0xc6820..0xc71b1  29 hits (0x8: 9, 0x10: 10, 0x20: 5, 0x28: 3, 0x30: 2)
0xc7490..0xc7ab3  46 hits (0x8: 15, 0x10: 18, 0x20: 6, 0x28: 5, 0x30: 2)
0xc7fc0..0xd0a9d  330 hits (0x8: 145, 0x10: 148, 0x20: 20, 0x28: 4, 0x30: 13)
0xd7740..0xf13ff  636 hits (0x8: 267, 0x10: 205, 0x20: 79, 0x28: 51, 0x30: 34)
0xf1a00..0xf4db6  71 hits (0x8: 15, 0x10: 36, 0x20: 14, 0x28: 3, 0x30: 3)
0xf4dc0..0xf6317  54 hits (0x8: 22, 0x10: 21, 0x20: 5, 0x28: 4, 0x30: 2)
0xf6320..0xf775f  76 hits (0x8: 24, 0x10: 17, 0x20: 15, 0x28: 11, 0x30: 9)
0xfb380..0xfb7f7  22 hits (0x8: 4, 0x10: 7, 0x20: 4, 0x28: 4, 0x30: 3)
0x103300..0x103490  12 hits (0x8: 4, 0x10: 3, 0x20: 1, 0x28: 2, 0x30: 2)
0x1050c0..0x108823  132 hits (0x8: 71, 0x10: 20, 0x20: 18, 0x28: 13, 0x30: 10)
0x108830..0x1209e7  604 hits (0x8: 178, 0x10: 180, 0x20: 96, 0x28: 82, 0x30: 68)
0x121090..0x1219cb  10 hits (0x8: 3, 0x10: 3, 0x20: 2, 0x28: 1, 0x30: 1)
0x1236e0..0x12394c  7 hits (0x8: 1, 0x10: 1, 0x20: 3, 0x28: 1, 0x30: 1)
```
*Output cut here: lines 1–40 of 162 shown.*

```stderr
xref: load 852.7µs, total 17.9ms
```
<!-- /xref -->

## Reading the output

- One line per instruction that accesses memory at one of the displacements through a non-stack base register: address, containing function, instruction.
- With several displacements and `--all`, only functions that use every one of them are listed; `--write` keeps stores, `--lea` keeps address computations, `--stride N` looks for array element strides.

### Serialized keys

`--who-serializes` answers "which key is this field written under?" for a struct whose serializer was derived. Such a serializer passes each field together with its key to one call: `serialize_field(state, "key", len, &self.field)` becomes a `(ptr, len)` key literal and `lea rcx, [rbx+OFF]` in argument registers right before the call. For each displacement the output names the key or says it is not serialized:

```text
+0x48  "frozen"
  "frozen"  in 0x401200  call 0x401236 -> 0x402a80  (lea rcx, [rbx+0x48])
+0x49  "mode"
  "mode"  in 0x401200  0x40125c  movzx eax, byte ptr [rbx+0x49]  (after the key call)
+0x4a  not serialized: 3 functions access it, none passes it with a key literal
```

- `call ADDR -> CALLEE` is the call taking both the key and the field: its address (`lea rcx, [rbx+OFF]`, or `add rbx, OFF` and a copy of `rbx`) or its loaded value. A field handed to a small helper that pairs it with the key reads `call ADDR -> HELPER -> CALLEE`.
- `(after the key call)` marks a read of the field within a few instructions after a call that took only the key: the key is written first and the value inline after it (`serialize_key` then a `true`/`false` write).
- Keys are searched in the functions with a memory access at the displacement. `--in FN` reads that one serializer whole, which also finds a field address made only with `add`.

On ripgrep, the serializer of a `--json` match record names two of its fields; the third (`line_number`, at +0) is passed as the struct pointer itself, which has no displacement to look for:

<!-- xref:run max=20 -->
```console
$ xref -b rg disp 0x20 0x40 --who-serializes --in 0x182d70
```

```text output
+0x20  "submatches"
  "submatches"  in 0x182d70  call 0x182f24 -> 0x15a5f0  (add rbx, 0x20)
+0x40  "absolute_offset"
  "absolute_offset"  in 0x182d70  call 0x182f04 -> 0x15ba20  (lea rcx, [rbx+0x40])
```

```stderr
xref: load 6.9ms, total 9.3ms
```
<!-- /xref -->

## Limits

- A displacement is a number, not a type: unrelated structures that use the same offset match too. Narrow with `--in FN` or combine offsets with `--all`, or use [`layout`](layout.md) on one function.
- `--who-serializes` sees the field at the displacement the serializer uses. A nested struct serialized by its own serializer (`lea rcx, [rbx+0x40]` passed for a key, the inner fields at small offsets inside it) is named at its own start, not at each inner field. For the opposite direction, key to offset, use [`field --within FN`](field.md).

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.5.0 (branch disp-who-serializes on main b527e4f) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
