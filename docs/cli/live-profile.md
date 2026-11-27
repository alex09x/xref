# xref live profile

Sample where a running process spends its CPU time and save a bounded
recording (`.xprof`) that the [`profile`](profile-report.md) commands read:
hot functions, blocks and instructions, with call chains unwound from
`.eh_frame` (`--callers dwarf`, the default). Recording can be limited to a
function (`--within`) or to windows opened by a uprobe trigger.

## Usage

<!-- xref:usage live profile -->
```text
xref live profile [OPTIONS]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live profile -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID; with --comm or --argv-match it may be left out to wait for the first match. |  |
| `--follow-children` | Also sample every process a sampled process forks (fork without exec), as it starts [alias: --follow-fork]. |  |
| `--comm <COMM>` | Also sample processes of the same executable with this name (`/proc/PID/comm`) as they start. |  |
| `--argv-match <ARGV_MATCH>` | Also sample processes of the same executable whose command line contains this text. |  |
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
$ xref -b rg live profile --pid 182538 --duration 2s --out rg.xprof
```

```text output
capture: 2000 ms, observer thread CPU: 27 ms (excludes target and interrupt-context overhead)
7892 samples, 0 lost, 0 dropped; partial=true
target mapping: /srv/xref-docs/rg
  20.96% self   20.96% total       1654 [kernel]:entry_SYSCALL_64
  20.48% self   30.06% total       1616 target:fn_430060
  11.05% self   12.02% total        872 target:fn_10b0c0
   6.59% self   44.75% total        520 target:unknown
   4.82% self   37.29% total        380 target:fn_de140
   3.50% self    3.50% total        276 [kernel]:__fsnotify_parent
   3.23% self    3.24% total        255 target:fn_4752a0
   2.72% self    2.72% total        215 [kernel]:vfs_write
   2.61% self    2.62% total        206 target:fn_4307b0
   2.48% self    6.99% total        196 target:fn_4302b0
   2.09% self    2.09% total        165 [kernel]:__fdget_pos
   1.99% self   39.28% total        157 target:fn_fb4b0
   1.96% self   32.44% total        155 target:fn_138ef0
   1.61% self    1.61% total        127 [kernel]:arch_exit_to_user_mode_prepare.isra.0
   1.37% self    1.37% total        108 [kernel]:apparmor_file_permission
   1.34% self   54.18% total        106 target:fn_fc020
   1.27% self    1.27% total        100 target:fn_42f380
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

### Daemons and processes that come and go

`--follow-children` also samples every process that a sampled process forks
without exec, such as a daemon started by `fork`, `setsid` and a second
`fork`. xref learns of a fork from the parent's perf fork record and, as a
fallback, from `/proc`. It accepts a process whose parent, process group or
session belongs to the target's family, so a daemon whose parent already
exited is still found.

`--comm NAME` and `--argv-match TEXT` add processes whose name or command line
matches, as they start. A benchmark that starts a new process every round is
profiled with one command. Without `--pid`, xref waits for the first match.
Every added process must run the same executable file (same device and inode)
as the target; others are refused and counted. A process that execs another
program leaves the profile. Each process keeps its own address layout, so
separately started instances are attributed correctly.

```sh
# The session daemon, a grandchild of the command that starts it:
sudo xref -b tako-session live profile --pid "$(pgrep -n tako)" --follow-children --duration 12s
# Every instance a benchmark starts during the window:
sudo xref -b tako-session live profile --comm tako-session --duration 12s --out bench.xprof
```

A process is sampled from when xref attaches to it: xref drains fork records
every 2 ms and scans `/proc` every 25 ms, so the first milliseconds of a
short-lived process can be missed. These options cannot be combined with
`--tid` or a trigger.

### macOS (Apple Silicon)

On macOS, `live profile` runs the system's `/usr/bin/sample` on the process.
`sample` pauses each thread at the interval (`--freq`, 1000 per second by
default) and walks its frame pointers, which arm64 macOS keeps. xref reads
the call tree it writes and saves the same `.xprof`, so `profile report`,
`profile diff` and `--within` work as on Linux. `-b` must be the process's
executable; xref checks its `LC_UUID`. An arm64 Mach-O is read for its
symbols and function starts only. `profile annotate` and `--by
block|line|instruction` need x86-64 code and are refused for it. `profile
diff --other` pairs the functions of two arm64 builds by symbol names unique
in both builds.

```sh
xref -b ./tako-session live profile --pid "$(pgrep -n tako-session)" --duration 12s --out after.xprof
xref -b ./tako-session-before profile diff before.xprof after.xprof --other ./tako-session
```

System libraries live in the dyld shared cache rather than in files, so their
frames are attributed to the library (`/usr/lib/system/libsystem_platform.dylib`
for `memset`), not to a function. A process of another user, or one with the
hardened runtime, needs `sudo`. `sample` gives counts per frame, not per
instruction, and whole seconds of capture: `--duration` must be whole seconds,
and `--period`, `--event`, `--callers lbr|none`, `--tid`, `--max-samples`,
`--include-kernel`, `--follow-children`, `--comm`, `--argv-match` and triggers
are refused. A universal binary is refused
too; give the slice the process runs (`lipo -thin arm64 APP -output
APP.arm64`).

## Limits

- Needs perf access to the process: with `kernel.perf_event_paranoid` 1 (the
  setting of the recording host) a user may profile their own processes; kernel
  samples need `--include-kernel` and a setting that allows them.
- `--out` does not overwrite an existing file.
- Chains whose unwinding stops (missing CFI, code outside the binary) are
  counted in the `warning:` lines rather than guessed.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.7.0 (the remapped release build of commit db9b69e, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
