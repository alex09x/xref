# xref layout

Reconstructed struct field layout accessed via an argument register (and optionally callees receiving it).

## Usage

<!-- xref:usage layout -->
```text
xref layout [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options layout -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | Function address or symbol name. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--reg <REG>` | Parameter or general-purpose register holding the struct pointer. | `rdi` |
| `--callees` | Follow direct/slot calls one hop where the struct pointer is forwarded. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### --reg rdi

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped layout 0xc7d60 --reg rdi
```

```text output
layout of rdi in 0xc7d60..0xc7fbf:
  +0       size  8  u64   r:0  w:1
  +8       size  8  u64   r:0  w:1
  +10      size  8  u64   r:0  w:1
3 fields (min span 0x18)
other pointer args: rsi (1 fields)  (use --reg <REG>)
```

```stderr
xref: load 458.9µs, total 1.5ms
```
<!-- /xref -->

### --reg rdi --callees

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped layout 0xc7d60 --reg rdi --callees
```

```text output
layout of rdi in 0xc7d60..0xc7fbf:
  +0       size  8  u64   r:0  w:1
  +8       size  8  u64   r:0  w:1
  +10      size  8  u64   r:0  w:1
3 fields (min span 0x18)
other pointer args: rsi (1 fields)  (use --reg <REG>)
```

```stderr
xref: load 605.6µs, total 1.7ms
```
<!-- /xref -->

### --reg rsi

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped layout 0xc7d60 --reg rsi
```

```text output
layout of rsi in 0xc7d60..0xc7fbf:
  +18      size  0  &sub  r:0  w:0   lea:1
1 fields (min span 0x19)
other pointer args: rdi (3 fields)  (use --reg <REG>)
```

```stderr
xref: load 471.6µs, total 1.5ms
```
<!-- /xref -->

### --reg rdi

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped layout 0x9a8a0 --reg rdi
```

```text output
layout of rdi in 0x9a8a0..0x9a97a:
  +0       size  8  u64   r:1  w:0   stride=0x8
  +8       size  8  u64   r:1  w:0
  +10      size  8  u64   r:1  w:0
  +18      size  8  u64   r:1  w:0
4 fields (min span 0x20)
```

```stderr
xref: load 478.3µs, total 1.6ms
```
<!-- /xref -->

## Reading the output

- The header names the register and function; each row is one field offset (hex), its access size, an inferred scalar type and the read/write counts (`r:0 w:1`).
- `N fields (min span …)` is how many distinct offsets were seen and the minimum extent they cover; `other pointer args` lists registers that also look like structure pointers.
- With `--callees`, offsets that a callee receiving the same pointer accesses are added and marked.

## Limits

- The layout is what this function touches; fields it never accesses are invisible, and the real size is unknown.
- Types are inferred from access widths and use, not from debug information.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
