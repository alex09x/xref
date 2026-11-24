# xref profile annotate

Show where inside one function the samples fell: its disassembly (or
pseudo-C with `--c`) with each line's share of the function and of the whole
profile.

## Usage

<!-- xref:usage profile annotate -->
```text
xref profile annotate [OPTIONS] <PROFILE> <FUNCTION>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options profile annotate -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<PROFILE>` | The `.xprof` recording. |  |
| `<FUNCTION>` | Function address or symbol name. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--c` | Annotate pseudo-C lines instead of assembly. |  |
| `--json` | Print the annotation as JSON. |  |
| `--min-samples <MIN_SAMPLES>` | Omit rows with fewer samples than this threshold. | `0` |
| `--percent <PERCENT>` | Which shares to print: of the function, of the whole profile, or both [possible values: both, function, profile]. | `both` |
<!-- /xref -->

## Examples

The profile is ripgrep filtering an endless input stream, recorded with
[`live profile`](live-profile.md).

### Hot instructions of one function

Only rows with at least one sample:

<!-- xref:run max=20 -->
```console
$ xref -b rg profile annotate rg.xprof 0x10b0c0 --min-samples 1
```

```text output
   0.44% function    0.05% profile        4 0x10b0c1  push r15
   0.11% function    0.01% profile        1 0x10b0cc  mov rbx, rdi
   0.11% function    0.01% profile        1 0x10b0de  test r8, r8
   0.11% function    0.01% profile        1 0x10b0e1  je short 0x10b0e9
   0.11% function    0.01% profile        1 0x10b0ed  cmp r9, [rcx+0x10]
   0.11% function    0.01% profile        1 0x10b0f1  jae short 0x10b0f9
   0.11% function    0.01% profile        1 0x10b11c  dec r8d
   0.11% function    0.01% profile        1 0x10b129  je short 0x10b13d
   0.22% function    0.03% profile        2 0x10b144  test byte ptr fs:[rax], 1
   0.11% function    0.01% profile        1 0x10b148  je 0x10b213
   0.11% function    0.01% profile        1 0x10b165  cmp rax, r8
   0.11% function    0.01% profile        1 0x10b188  mov byte ptr [rsp+0x18], 0
   0.55% function    0.07% profile        5 0x10b191  mov rax, [rsi+0x18]
   0.33% function    0.04% profile        3 0x10b199  dec rsi
   0.11% function    0.01% profile        1 0x10b1a3  add rsi, 0x10
   0.33% function    0.04% profile        3 0x10b1bb  mov rsi, [rsp+8]
   0.11% function    0.01% profile        1 0x10b1c8  je short 0x10b1df
   0.44% function    0.05% profile        4 0x10b1cf  cmp rsi, 2
   0.76% function    0.10% profile        7 0x10b1d3  je 0x10b29b
   0.55% function    0.07% profile        5 0x10b1dd  jmp short 0x10b1f5
```
*Output cut here: lines 1–20 of 26 shown.*

```stderr
xref: load 3.8ms, total 126.2ms
```
<!-- /xref -->

## Reading the output

- Each row: the share of the function's samples, the share of the whole
  profile, the sample count, the address and the instruction. Samples land on
  the instruction the CPU reported, which is often the one after a slow load
  (skid).

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
