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
   0.10% function    0.01% profile        1 0x10b0cc  mov rbx, rdi
   0.10% function    0.01% profile        1 0x10b0de  test r8, r8
  99.59% function   12.25% profile      981 0x10b1fa  mov [rbx+0x10], rax
   0.10% function    0.01% profile        1 0x10b203  movups [rbx], xmm0
   0.10% function    0.01% profile        1 0x10b206  add rsp, 0x70
```

```stderr
xref: load 2.6ms, total 22.9ms
```
<!-- /xref -->

## Reading the output

- Each row: the share of the function's samples, the share of the whole
  profile, the sample count, the address and the instruction. Samples land on
  the instruction the CPU reported, which is often the one after a slow load
  (skid).

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
