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
7347 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  30.43% self   30.43% total       2236 [kernel]:unknown
  17.35% self   26.09% total       1275 target:fn_430060
  12.48% self   15.56% total        917 target:fn_10b0c0
  10.04% self   42.77% total        738 target:fn_de140
   4.57% self   32.72% total        336 target:fn_138ef0
   3.85% self   46.62% total        283 target:fn_fb4b0
   3.66% self    3.66% total        269 target:fn_4307b0
   2.49% self    2.49% total        183 target:unknown
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
warning: unknown_or_unavailable_callchain_mode
warning: unresolved_frames_preserved_by_module
```

```stderr
xref: load 3.8ms, total 63.2ms
```
<!-- /xref -->

### Hottest instructions

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg.xprof --top 6 --by instruction
```

```text output
7347 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  16.88%       1240 0x43009e
  11.53%        847 0x10b1fa
   3.27%        240 0x138ef1
   2.71%        199 0xe2eae
   1.57%        115 0xe3042
   1.21%         89 0x13af52
warning: capture_coverage_is_incomplete
warning: cfi_unwind_stopped_cfa_register_unavailable
warning: cfi_unwind_stopped_outside_mapped_function
warning: cfi_unwind_stopped_return_address_unavailable
```
*Output cut here: lines 1–12 of 14 shown.*

```stderr
xref: load 4.9ms, total 61.4ms
```
<!-- /xref -->

## Reading the output

- The first line: samples, lost and dropped samples, and `partial=true` when
  some call chains could not be unwound completely.
- Each row: self share (samples in the function itself), total share (samples
  with the function anywhere on the stack), self sample count, and the frame:
  `target:fn_ADDR` for code in the binary, `target:unknown` for samples in the
  binary outside any known function, `[kernel]` or a library for the rest.
- Library frames are named like the binary's (`libc.so.6:memset`), from the
  library's own `.symtab` and `.dynsym`. A stripped library is also named from
  its separate debug file (`/usr/lib/debug/.build-id/…`, `.gnu_debuglink`, or
  debuginfod when `DEBUGINFOD_URLS` is set and `debuginfod-find` is installed),
  which has the internal names such as `__memset_avx2_unaligned_erms`. Without
  one, an internal implementation that an exported IFUNC resolver selects is
  named after the IFUNC (`memset`). Kernel frames are named from
  `/proc/kallsyms` (readable as root), except code of loadable modules, whose
  addresses can be reused within a boot, and `[vdso]` frames from the vdso. Both
  get names only when the report runs in the boot the recording was made in,
  because kernel addresses change with every boot.
- `warning:` lines name the reasons a chain stopped; they are counted, not
  hidden.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
