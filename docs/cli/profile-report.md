# xref profile report

Summarize a recorded profile (`.xprof`, from [`live profile`](live-profile.md)
or [`profile import`](profile-import.md)): the hottest functions, basic
blocks, source lines, caller paths or instructions, with self and total
shares.

## Usage

<!-- xref:usage profile report -->
```text
xref profile report [OPTIONS] <PROFILE>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options profile report -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<PROFILE>` | The `.xprof` recording. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--top <TOP>` | Number of rows to print. | `30` |
| `--by <BY>` | What a row aggregates: function, basic block, source line, caller path or instruction [possible values: function, block, line, caller-path, instruction]. | `function` |
| `--json` | Print the report as JSON. |  |
| `--folded <FOLDED>` | Also write folded stacks (flame-graph input) to this file. |  |
| `--within <WITHIN>` | Keep samples whose call chain includes this function or address. |  |
| `--window <WINDOW>` | Select one captured trigger window (numbered from one). |  |
| `--merge-windows` | Report the union of all captured windows. |  |
<!-- /xref -->

## Examples

The profile is ripgrep filtering an endless input stream, recorded with
[`live profile`](live-profile.md).

### Hottest functions

<!-- xref:run max=20 -->
```console
$ xref -b rg profile report rg.xprof --top 8
```

```text output
7999 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  50.89% self   50.89% total       4071 [kernel]:unknown
  19.71% self   27.73% total       1577 target:fn_430060
  11.56% self   11.61% total        925 target:fn_10b0c0
   8.98% self    8.98% total        718 target:unknown
   3.55% self    3.55% total        284 target:fn_4752a0
   3.49% self    7.79% total        279 target:fn_4302b0
   0.75% self    0.75% total         60 target:fn_42f380
   0.31% self    0.31% total         25 target:fn_4307b0
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
warning: unknown_or_unavailable_callchain_mode
warning: unresolved_frames_preserved_by_module
```

```stderr
xref: load 2.3ms, total 22.6ms
```
<!-- /xref -->

### Hottest instructions

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg.xprof --top 6 --by instruction
```

```text output
7999 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  19.68%       1574 0x43009e
  11.56%        925 0x10b1fa
   6.61%        529 0x469f32
   3.29%        263 0x4752a1
   2.68%        214 0x4302c1
   1.46%        117 0x469f18
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
```
*Output cut here: lines 1–12 of 14 shown.*

```stderr
xref: load 2.5ms, total 21.6ms
```
<!-- /xref -->

## Reading the output

- The first line: samples, lost and dropped samples, and `partial=true` when
  some call chains could not be unwound completely.
- Each row: self share (samples in the function itself), total share (samples
  with the function anywhere on the stack), self sample count, and the frame:
  `target:fn_ADDR` for code in the binary, `target:unknown` for samples in the
  binary outside any known function, `[kernel]` or a library for the rest.
- `warning:` lines name the reasons a chain stopped; they are counted, not
  hidden.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
