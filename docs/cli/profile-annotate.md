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
 100.00% function   11.56% profile      925 0x10b1fa  mov [rbx+0x10], rax
```

```stderr
xref: load 2.6ms, total 21.9ms
```
<!-- /xref -->

## Reading the output

- Each row: the share of the function's samples, the share of the whole
  profile, the sample count, the address and the instruction. Samples land on
  the instruction the CPU reported, which is often the one after a slow load
  (skid).

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
