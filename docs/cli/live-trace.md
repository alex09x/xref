# xref live trace

Record what a thread does between two points: each time a thread enters a
`--start` function, xref opens a window for that thread and records, in
order, the entries and returns of the traced functions until the window
closes (`--stop-return` of the start function, or `--stop` at an address).
`--callees-of` traces every static call site of a function, so one command
shows what it calls and in which order. Uses Linux `tracefs` uprobes.

## Usage

<!-- xref:usage live trace -->
```text
xref live trace [OPTIONS] --pid <PID> --start <VA>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live trace -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--start <VA>` | Start address opening a thread-scoped trace window (`0x...` hex or decimal; repeatable). |  |
| `--start-filter <PRED>` | Numeric predicate gating window creation on `--start` fetches (`FIELD <OP> INTEGER`; repeatable). |  |
| `--stop-return <VA>` | Close an active window on the matching return of this `--start` function (`0x...` or decimal). |  |
| `--stop <VA>` | Close an active window when its thread reaches this address (`0x...` or decimal). |  |
| `--functions <VA>` | Comma-separated or repeated function entry addresses to trace (`VA,VA,...`). |  |
| `--callees-of <FN>` | Expand static call sites and post-call return sites from function `FN` (`0x...` or symbol). |  |
| `--depth <N>` | Static callee expansion depth for `--callees-of` (`1..=16`, defaults to `1`). |  |
| `--fetch <NAME=EXPR>` | Fetch expression(s) attached to `--start` probes (`NAME=EXPR[,NAME=EXPR...]`). |  |
| `--fetch-at <VA> <NAME=EXPR,...>` | Attach entry/call-site fetch expressions at `VA` (`--fetch-at VA "NAME=EXPR,..."`). |  |
| `--fetch-ret <VA> <NAME=EXPR,...>` | Attach return fetch expressions for `VA` (`--fetch-ret VA "NAME=EXPR,..."`). |  |
| `--max-windows <N>` | Stop and detach after completing this many trace windows (`1..=4096`). |  |
| `--max-events <N>` | Stop and detach after recording this many trace events (`1..=65536`). |  |
| `--duration-ms <MS>` | Observation duration in milliseconds (`0` runs until limits, target exit, or `SIGINT`). |  |
| `--force-bin` | Rejects unverified binary mismatches; accepted for CLI symmetry with other `live` commands. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`) filtering an endless input stream, as on
[`live maps`](live-maps.md). PIDs and runtime addresses belong to that run.

### What one call of a hot function does

<!-- xref:run max=30 -->
```console
$ sudo xref -b rg live trace --pid 4084848 --start 0x430060 --stop-return 0x430060 --callees-of 0x430060 --max-windows 2 --duration-ms 1000
```

```text output
pid 4084848  match verified_sha256  slide +0x75a99f000000  backend tracefs  return_mode mixed_uretprobe_best_effort
warning: uretprobe_returns_are_best_effort_under_unwind
window 1  tid 4084848  start 0x430060  status complete  stop 0x430060
   0  > 0x430060 @0x138f62
   1    > 0x4307b0 @0x430070
   1    < 0x4307b0
   1    > 0x4302b0 @0x430087
   1    < 0x4302b0
   0  < 0x430060
window 2  tid 4084848  start 0x430060  status complete  stop 0x430060
   0  > 0x430060 @0x138f62
   1    > 0x4307b0 @0x430070
   1    < 0x4307b0
   1    > 0x4302b0 @0x430087
   1    < 0x4302b0
   0  < 0x430060
summary: windows=2 events=12 lost=0 stop=max_windows elapsed_ms=8
```

```stderr
xref: probe_ready {"backend":"tracefs","pid":4084848,"attached_tids":[4084848],"probes":["0x430060","0x430070","0x430076","0x430087","0x43008d","0x4300c1","0x4300c7","0x4300de","0x4300e3","0x4300e6","0x430060"],"tracefs_instance":"xref_trace_4084848_003e5b8b1a5041d5","uprobe_events":["xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_0","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_1","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_2","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_3","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_4","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_5","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_6","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_7","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_8","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_9","xt_003e5b8b1a5041d5/xt_003e5b8b1a5041d5_10"]}
```
<!-- /xref -->

## Reading the output

- `probe_ready` on stderr lists every probe and the private `tracefs`
  instance; the instance is removed when the command ends.
- Each `window` is one thread's run from start to stop. Rows are depth, `>`
  entry or `<` return, the function, and for entries the call site (`@`).
  Here both windows show the same sequence: `0x430060` calls `0x4307b0`, then
  `0x4302b0`, and returns.
- `summary`: windows and events recorded, lost events, why it stopped.

## Limits

- Needs root (tracefs uprobes).
- Returns are recorded with uretprobes, which are best effort when the stack
  is unwound by panics or `longjmp`; the warning says so.
- Windows are per thread; calls on other threads do not appear in them.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
