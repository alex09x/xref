# xref live profile

Sample where a running process spends its CPU time and save a bounded
recording (`.xprof`) that the [`profile`](profile-report.md) commands read:
hot functions, blocks and instructions, with call chains unwound from
`.eh_frame` (`--callers dwarf`, the default). Recording can be limited to a
function (`--within`) or to windows opened by a uprobe trigger.

## Usage

<!-- xref:usage live profile -->
```text
xref live profile [OPTIONS] --pid <PID>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live profile -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID. |  |
| `--duration <DURATION>` | Capture duration, e.g. 10s or 200ms. | `10s` |
| `--duration-ms <DURATION_MS>` | Capture duration in milliseconds. |  |
| `--freq <FREQ>` | Requested samples per second per thread; defaults to 4000 [alias: --hz]. |  |
| `--period <PERIOD>` | Hardware events per sample instead of a frequency. |  |
| `--event <EVENT>` | Hardware event that drives sampling [possible values: cycles, instructions, cache-misses, branch-misses]. | `cycles` |
| `--tid <TIDS>` | Sample only this thread ID (repeatable); all threads by default. |  |
| `--callers <CALLERS>` | How call chains are recorded: DWARF stack copies unwound with `.eh_frame`, LBR, frame pointers, or none [alias: --callgraph] [possible values: dwarf, lbr, fp, none]. | `dwarf` |
| `--within <WITHIN>` | Report only samples whose call chain includes this function or address (repeatable). |  |
| `--trigger-probe <TRIGGER_PROBE>` | Code address whose uprobe hits open recording windows; without it the whole duration is recorded. |  |
| `--window <WINDOW>` | Length of each trigger window, e.g. 200ms (the default). |  |
| `--window-ms <WINDOW_MS>` | Length of each trigger window in milliseconds. |  |
| `--max-windows <MAX_WINDOWS>` | Record up to this many separate post-trigger windows. |  |
| `--trigger-fetch <TRIGGER_FETCH>` | Named tracefs fetch, e.g. op=+40(%sp):u64, for trigger filtering. |  |
| `--trigger-filter <TRIGGER_FILTER>` | Numeric predicate over a named trigger fetch. |  |
| `--json` | Print the capture statistics and the report as JSON. |  |
| `--folded <FOLDED>` | Also write folded stacks (flame-graph input) to this new file. |  |
| `--out <OUT>` | Keep the `.xprof` recording at this new path; without it a temporary recording is deleted after the report. |  |
| `--max-samples <MAX_SAMPLES>` | Stop recording after this many samples. | `10000000` |
| `--stack-bytes <STACK_BYTES>` | User stack bytes copied with each sample for DWARF unwinding. | `2048` |
| `--include-kernel` | Include kernel-mode samples; requires suitable perf permissions. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`) filtering an endless input stream, as on
[`live maps`](live-maps.md). PIDs and runtime addresses belong to that run.

### Record two seconds

<!-- xref:run max=20 -->
```console
$ xref -b rg live profile --pid 4060909 --duration 2s --out rg.xprof
```

```text output
capture: 2000 ms, observer thread CPU: 15 ms (excludes target and interrupt-context overhead)
7996 samples, 0 lost, 0 dropped; partial=true
target mapping: /home/alex09x/xref-docs/rg
  46.26% self   46.26% total       3699 [kernel]:unknown
  19.76% self   27.05% total       1580 target:fn_430060
  14.16% self   14.16% total       1132 target:unknown
  11.87% self   11.88% total        949 target:fn_10b0c0
   3.39% self    3.39% total        271 target:fn_4752a0
   3.18% self    7.20% total        254 target:fn_4302b0
   0.64% self    0.64% total         51 target:fn_42f380
   0.35% self    0.35% total         28 target:fn_406150
   0.14% self    0.14% total         11 target:fn_4307b0
   0.08% self   27.19% total          6 target:fn_fb4b0
   0.08% self   27.11% total          6 target:fn_de140
   0.05% self   39.14% total          4 target:fn_fc020
   0.01% self   27.04% total          1 target:fn_138ef0
   0.01% self    0.36% total          1 target:fn_406fd0
   0.01% self    0.01% total          1 target:fn_13af50
   0.01% self    0.01% total          1 target:fn_2387b0
   0.01% self    0.01% total          1 target:fn_408bf0
```
*Output cut here: lines 1–20 of 32 shown.*
<!-- /xref -->

The summary printed after the capture is the same report as
[`profile report`](profile-report.md). Samples in shared libraries and the
kernel are kept as `unknown` frames of their module, never attributed to the
target.

## Limits

- Needs perf access to the process: with `kernel.perf_event_paranoid` 1 (the
  setting of the recording host) a user may profile their own processes; kernel
  samples need `--include-kernel` and a setting that allows them.
- `--out` does not overwrite an existing file.
- Chains whose unwinding stops (missing CFI, code outside the binary) are
  counted in the `warning:` lines rather than guessed.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
