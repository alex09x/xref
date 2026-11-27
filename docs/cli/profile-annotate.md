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
   0.11% function    0.01% profile        1 0x10b0d7  mov rax, [rax+0xa8]
   0.23% function    0.03% profile        2 0x10b0fc  jne short 0x10b13d
   0.11% function    0.01% profile        1 0x10b11c  dec r8d
   0.11% function    0.01% profile        1 0x10b123  jb short 0x10b12b
   0.11% function    0.01% profile        1 0x10b129  je short 0x10b13d
   0.11% function    0.01% profile        1 0x10b161  mov r8, [rdx+0x28]
   0.11% function    0.01% profile        1 0x10b1bb  mov rsi, [rsp+8]
   0.34% function    0.04% profile        3 0x10b1d3  je 0x10b29b
   0.34% function    0.04% profile        3 0x10b1dd  jmp short 0x10b1f5
  97.48% function   10.77% profile      850 0x10b1fa  mov [rbx+0x10], rax
   0.11% function    0.01% profile        1 0x10b203  movups [rbx], xmm0
   0.46% function    0.05% profile        4 0x10b206  add rsp, 0x70
   0.11% function    0.01% profile        1 0x10b20a  pop rbx
   0.23% function    0.03% profile        2 0x10b212  ret
```

```stderr
xref: load 2.3ms, total 178.3ms
```
<!-- /xref -->

## Reading the output

- Each row: the share of the function's samples, the share of the whole
  profile, the sample count, the address and the instruction. Samples land on
  the instruction the CPU reported, which is often the one after a slow load
  (skid).

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.7.0 (the remapped release build of commit db9b69e, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
