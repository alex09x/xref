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
$ xref -b rg live profile --pid 3669251 --duration 2s --out rg.xprof
```

```text output
capture: 2000 ms, observer thread CPU: 34 ms (excludes target and interrupt-context overhead)
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
   2.26% self    2.26% total        166 target:fn_408bf0
   2.22% self    2.22% total        163 target:fn_4752a0
   2.18% self   66.68% total        160 target:fn_fc020
   2.06% self    2.06% total        151 target:fn_13af50
   1.70% self    5.09% total        125 target:fn_4302b0
   1.17% self    1.17% total         86 target:fn_42f380
   0.83% self    0.83% total         61 target:fn_4062e0
   0.68% self    0.68% total         50 target:fn_406150
   0.59% self    3.08% total         43 target:fn_319d40
```
*Output cut here: lines 1–20 of 39 shown.*
<!-- /xref -->

The summary printed after the capture is the same report as
[`profile report`](profile-report.md). Samples are never attributed to the
target when they fall outside it. A shared library whose file on disk is
verified to be the one mapped in the process is symbolized as its own module;
a library that cannot be verified (changed or missing file) or has no
symbols, and kernel samples, stay `unknown` frames of their module, as
`[kernel]:unknown` does here.

## Limits

- Needs perf access to the process: with `kernel.perf_event_paranoid` 1 (the
  setting of the recording host) a user may profile their own processes; kernel
  samples need `--include-kernel` and a setting that allows them.
- `--out` does not overwrite an existing file.
- Chains whose unwinding stops (missing CFI, code outside the binary) are
  counted in the `warning:` lines rather than guessed.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
