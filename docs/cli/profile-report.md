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
7994 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  46.01% self   46.01% total       3678 [kernel]:unknown
  19.76% self   27.72% total       1580 target:fn_430060
  14.07% self   14.07% total       1125 target:unknown
  11.72% self   11.73% total        937 target:fn_10b0c0
   3.44% self    7.91% total        275 target:fn_4302b0
   3.34% self    3.34% total        267 target:fn_4752a0
   1.13% self    1.13% total         90 target:fn_42f380
   0.14% self    0.14% total         11 target:fn_406150
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
warning: unknown_or_unavailable_callchain_mode
warning: unresolved_frames_preserved_by_module
```

```stderr
xref: load 2.1ms, total 20.6ms
```
<!-- /xref -->

### Hottest instructions

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg.xprof --top 6 --by instruction
```

```text output
7994 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  19.75%       1579 0x43009e
  11.68%        934 0x10b1fa
   7.54%        603 0x469f32
   6.30%        504 0x467b7d
   3.18%        254 0x4752a1
   2.55%        204 0x4302c1
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
```
*Output cut here: lines 1–12 of 14 shown.*

```stderr
xref: load 2.2ms, total 22.2ms
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
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
