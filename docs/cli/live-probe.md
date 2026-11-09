# xref live probe

Count how often code runs in a live process, and who calls it: xref attaches
uprobes to static code addresses (translated through the verified PIE slide),
counts hits per probe, and with `--callers` recovers each caller's return
address from `.eh_frame` and checks that it follows a call instruction.

## Usage

<!-- xref:usage live probe -->
```text
xref live probe [OPTIONS] --pid <PID> <ADDR>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live probe -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>...` | Target static or runtime code addresses (`0x...` hex or decimal). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--backend <BACKEND>` | Kernel tracing backend (`perf` binary ring buffer by default; never silently falls back on EACCES). Values: `perf` (Primary native `perf_event_open` + `mmap` binary ring-buffer backend); `tracefs` (Explicit Linux `tracefs` (`uprobe_events` + isolated `instances/`) adapter). | `perf` |
| `--count` | Explicitly request hit-count reporting (enabled by default). |  |
| `--callers` | Recover and verify caller return addresses using effective `.eh_frame` CFI. |  |
| `--regs` | Sample argument/return registers (`rdi..r9`, `rax`, `rsp`, `rbp`) on accepted hits. |  |
| `--duration-ms <DURATION_MS>` | Observation window duration in milliseconds (`0..=60000`, 0 runs until --until-hits, target exit, or SIGINT). | `1000` |
| `--heartbeat-ms <MS>` | Periodic progress heartbeat interval in milliseconds (`1..=60000`). |  |
| `--group-by <KEY>` | Group hits by key (`ret` for return site). |  |
| `--json-lines` | Print one JSON object per hit (va, tid, fetch, ret, mark) as it happens, on either backend and for any duration; the last line is the full report. |  |
| `--mark-file <PATH>` | File to tail for mark annotations. |  |
| `--mark-regex <REGEX>` | Regular expression to match lines in --mark-file. |  |
| `--max-events <MAX_EVENTS>` | Maximum accepted probe events before stopping (`1..=65536`). Defaults to 4096, or no limit with `--duration-ms 0`, so unbounded runs end on --until-hits, exit or SIGINT. |  |
| `--fetch <NAME=EXPR>` | Tracefs uprobe fetch argument (`NAME=+OFFSET(%reg):u64`); repeatable, tracefs backend only. |  |
| `--filter <PREDICATE>` | Tracefs numeric value predicate (`rdi == 0x...` or `NAME > N`); repeatable. |  |
| `--every <EVERY>` | Record every Nth matching tracefs event per probe (`1..=1000000`). | `1` |
| `--first <FIRST>` | Stop recording after the first N matching events per probe (`1..=65536`). |  |
| `--until-hits <UNTIL_HITS>` | Stop the session after this many accepted hits across probes (`1..=65536`). |  |
| `--force-bin` | Rejects unverified mismatches; accepted for CLI symmetry with `maps`/`resolve`. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`) filtering an endless input stream, as on
[`live maps`](live-maps.md). PIDs and runtime addresses belong to that run.

### Hit counts and callers of two hot functions

<!-- xref:run max=20 -->
```console
$ sudo xref -b rg live probe --pid 222207 0x10b0c0 0x430060 --callers --duration-ms 500
```

```text output
pid 222207  starttime 1515210451  match verified_sha256  pie_slide +0x7cf645800000  alive true  changed false
backend perf  pid_isolated_bp true  elapsed 34ms/500ms  stop max_events  seeded_tids 1  dyn_tids 0  excluded_tgid 0  lost 87248 (lower_bound)
probe static 0x10b0c0  runtime 0x7cf64590b0c0  file 0x10b0c0  insn push    cfi entry_rsp+8_ra-8    fn 0x10b0c0 (-)  hits 2110
  caller ra 0x7cf6458fc5ec (static 0xfc5ec)  fn 0xfc020  call_site 0xfc5e7  verified true  hits 2110  [unwind_evidence_only_tail_call_possible]
probe static 0x430060  runtime 0x7cf645c30060  file 0x430060  insn push    cfi entry_rsp+8_ra-8    fn 0x430060 (-)  hits 1986
  caller ra 0x7cf645938f67 (static 0x138f67)  fn 0x138ef0  call_site 0x138f62  verified true  hits 1986  [unwind_evidence_only_tail_call_possible]
```

```stderr
xref: probe_ready {"backend":"perf","pid":222207,"attached_tids":[222207],"probes":["0x10b0c0","0x430060"]}
```
<!-- /xref -->

## Reading the output

- `probe_ready` on stderr: the probes are attached; what the target does after
  it is counted.
- The session line: backend, elapsed time against the window, why it stopped
  (`max_events` here: the 4096-event default was reached within milliseconds,
  because ripgrep calls these functions for every line), and `lost` events the
  ring buffer dropped (a lower bound).
- One block per probe: static and runtime address, the first instruction and
  its CFI state, the hit count, and with `--callers` each verified caller:
  return address, caller function, call site and its hits.
  `unwind_evidence_only_tail_call_possible` says the caller was found by
  unwinding, so a tail call in between cannot be ruled out.

## Limits

- Opening uprobes on another process needs privileged perf access (root, or
  capabilities and `kernel.perf_event_paranoid` settings that allow it).
- Busy functions reach `--max-events` quickly; raise it, or bound the run with
  `--until-hits`, or sample with `--every N` on the tracefs backend.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
