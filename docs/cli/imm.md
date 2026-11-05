# xref imm

Instructions with an immediate operand.

Filters immediate operands across decoded x86-64 instructions, narrowing to cmp/test guards (--cmp) or direct constant stores (--store).

## Usage

<!-- xref:usage imm -->
```text
xref imm [OPTIONS] <VALUE>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options imm -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<VALUE>` | Immediate value (`0x...` hex or decimal). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--store` | Only `mov [memory], imm`. |  |
| `--cmp` | Only `cmp`. |  |
| `--in <WITHIN>` | Only inside the function containing this address. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Imm 24 --in 0xc7d60

Every immediate 24 (0x18, struct element stride) inside 0xc7d60.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped imm 24 --in 0xc7d60
```

```text output
0xc7de0  in 0xc7d60  add r14, 0x18
1 hits
```

```stderr
xref: load 472.3µs, total 1.6ms
```
<!-- /xref -->

### Imm 59 --cmp --in 0xc7d60

Only cmp instructions testing against immediate 59 (ASCII ";") inside 0xc7d60.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped imm 59 --cmp --in 0xc7d60
```

```text output
0xc7e4d  in 0xc7d60  cmp byte ptr [rbx+rbp-1], 0x3b
1 hits
```

```stderr
xref: load 479.5µs, total 1.6ms
```
<!-- /xref -->

### Imm 8 --store --in 0xc7d60

Only instructions storing constant 8 directly to memory inside 0xc7d60.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped imm 8 --store --in 0xc7d60
```

```text output
0xc7d7e  in 0xc7d60  mov qword ptr [rsp+8], 8
1 hits
```

```stderr
xref: load 455.9µs, total 1.6ms
```
<!-- /xref -->

## Reading the output

- One line per instruction with the immediate operand: address, containing function, instruction. `--store` keeps stores of the value, `--cmp` comparisons, `--in FN` limits to one function.

## Limits

- The value is matched as an encoded operand; constants built from several instructions or loaded from memory are not found.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
