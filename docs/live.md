# Linux live analysis: architecture and acceptance contract

Status: implemented across Stages L1 (`PR #49`), L2 (`PR #53`), L3 Increment 1
(`PR #54`), L3 Increment 2 (`PR #55`), and L4 for
[issue #46](https://github.com/alex09x/xref/issues/46). Available starting with
v0.3.0; the published `v0.2.0` and earlier binaries do not contain `xref live`
or the opt-in `xref_live` MCP tool.

For a recorded, step-by-step example with real commands and their output
(memscan → resolve → refs/c → probe → watch → `--follow` after a buffer move),
see the [Live Analysis walkthrough](live-walkthrough.md), also published at
[xrefcode.com/live-walkthrough](https://xrefcode.com/live-walkthrough).

The goal is to connect a running Linux x86-64 process to XRef's static
address/function evidence: find state, observe selected calls, and identify
candidate instructions that modify selected memory. Each result must distinguish
an observation from an inference and state its coverage and limits.

## Delivery order

1. **L1: process identity, mappings, address resolution and memory search.**
   Use safe standard-library reads, bounded output and controlled synthetic
   target processes. This is the first independently reviewable deliverable.
2. **L2: function hit counts, followed by caller/register evidence.**
   Validate the Linux tracing adapter on a synthetic fixture before adding it.
3. **L3: hardware write watchpoints.** Validate event/IP/value semantics and
   thread/resource coverage separately; preserve unknowns.
4. **L4: explicitly enabled live MCP.** Add a PID-bound live context only after
   cancellation, process lifetime and backend cleanup have been validated.

The issue remains open while requested later stages are outstanding. Source
changes use isolated worktrees, focused development tests, a completed-change
final gate, independent review and explicit integration. Implementing L1 does
not imply publishing a new release or tracing a production process.

## Architecture and platform boundaries

- Preserve the existing static `Analysis`, JSON queries and default
  [`xref_query` MCP contract](mcp.md): one immutable selected image.
- A separate live `ProcessContext` owns the selected PID, lifetime/executable
  identity, mapping observations and read handles. A request cannot silently
  redirect that context to another PID.
- Keep `unsafe_code = "forbid"` in the project crate. L1 can use
  `std::fs` and Unix `FileExt::read_at`; later tracing uses an optional,
  validated Linux adapter. Avoid a mandatory new debugger or BPF compiler.
- Initial live support is Linux x86-64 with an ELF executable. Preserve macOS
  host builds and report `unsupported_platform` for unavailable live commands.
  Existing static Mach-O support is a separate capability.
- Keep modules focused and below the source-size limit. Suggested boundaries:
  CLI/types, proc parsing, process identity/I/O, ELF/load-map resolution,
  scanning, word classification and rendering.

## L1: identify the process and translate addresses

Stage L1 (`maps`, `resolve`, `memscan`) command shapes:

```sh
xref live maps --pid PID --json
xref live resolve --pid PID LIVE_VA... --json
xref -b app.elf live resolve --pid PID LIVE_VA... --json
```

1. Validate the PID. Open and retain proc/executable handles, record the PID's
   start identity and executable identity, and hash the actual executable bytes.
   A numeric PID alone is insufficient because a PID can be reused.
2. If `--bin` is supplied, verify it identifies the process's executable build.
   An identical copy can be accepted by digest; a coincidental filename cannot.
   Resolve the executable automatically when no binary path is supplied.
   Static commands retain their requirement for a selected binary.
3. Read bounded `maps`/`smaps` metadata. Preserve paths as reported, including
   spaces, escape spelling and deleted-file suffixes; paths are labels rather
   than authority to open arbitrary files.
4. Obtain ELF load-segment geometry and flags. Do not infer executable status
   from the existing `Segment { va, offset, size }` fields alone.
5. Distinguish **static VA**, **file offset** and **live VA** explicitly. Check
   the relevant load segment, its file-backed extent, mapping identity and load
   bias. Never apply one unexplained global subtraction to every mapping.
6. Preserve multiple valid interpretations as candidates. Bytes in an anonymous
   mapping or a zero-filled segment tail are not automatically file-backed code.
7. Recheck process/executable identity at operation boundaries. Report process
   exit, replacement, image mismatch and mapping changes explicitly; do not
   quietly attribute data from a changed process to the original image.

Return raw addresses and mapping provenance when static function attribution is
unavailable. An `.eh_frame` FDE range is not proof of a source-level function.

## L1: search memory and show a compact context window

Proposed command shape:

```sh
xref live memscan --pid PID U64_VALUE... --before-words 2 --after-words 6 --max-hits 32 --json
```

The input is a bounded sequence of little-endian `u64` values. Matches start at
8-byte-aligned live addresses. Limit pattern length, requested/read bytes,
result count, context words and total serialized output.

### Region selection and scanning

- Default to eligible private anonymous/heap/stack mappings and verified private
  data mappings of the selected executable. Skip shared/device/IO/PFN and
  unclassified mappings with an explicit reason. Missing flags are not proof
  that a special mapping is ordinary RAM.
- Scan in bounded chunks. Keep enough overlap to match a pattern crossing a
  contiguous chunk boundary, without emitting duplicate hits.
- Treat short reads, inaccessible pages, mapping changes and EOF separately.
  Do not bridge an unreadable gap with overlap bytes, fabricate zero-filled
  data, or report a complete negative result after skipping unreadable memory.
- Use checked address/length arithmetic. Recovery from an unreadable span must
  advance and remain bounded; it must not retry forever at the same address.
- Check the deadline between reads. Standard proc-memory reads can block in
  the kernel, so this is a cooperative elapsed-time budget, not a hard
  real-time timeout. Report actual elapsed time and the stop reason.
- Memory changes while it is being read. The result is an observation during
  an interval, not an atomic process snapshot or a claim that a source object
  has been reconstructed.

### Context window and pointer hints

Return a compact window of aligned words around each match, rather than an
unbounded memory dump. The proposed defaults are two words before and six words
after, with at most 32 hits. These are upper bounds: output/region/read limits
can shorten a window or stop the result earlier, and that loss must be visible.

Each slot carries its address, exact observed word when readable, classification
and evidence. Serialize 64-bit addresses/words without losing integer precision.
Do not silently read across an excluded mapping or guard gap to fill a window.

Candidate classifications:

- `code_ptr`: the value maps to the selected executable and a recovered static
  range; include live/static VA and range provenance. Otherwise retain an
  executable-mapping pointer without inventing a function identity.
- Pointer to a known static pointer/relocation or read-only region: provide the
  relevant evidence. This alone does not prove a C++/Rust vtable or object type.
- Static data pointer: optionally preview bounded ASCII from verified **file
  bytes**, distinguishing that preview from bytes read from live memory.
- Heap/stack/mapped pointer candidate: report the containing mapping. Mapping
  membership does not establish allocation ownership or object bounds.
- Scalar/unclassified word: retain the actual value. An unreadable or partial
  word has a separate status and must not become a scalar zero.

## Result and failure contract

The human CLI and JSON output share the same typed live result. Keep a versioned
envelope with tool/version, operation, process/image identity, observation
interval, mapping identity, data/error, warnings, coverage, limits and stops.
The existing static JSON/MCP schema does not silently acquire arbitrary PID access.

Examples of necessary distinctions:

- `permission_denied` versus an empty match list;
- `process_exited`/`process_changed` versus an image that has no matching code;
- unreadable/skipped memory versus memory that was examined and did not match;
- budget/result/output exhaustion versus a complete result for the stated scope;
- a mapping/pointer candidate versus a recovered source type or exact past value.

The live reader does not write target memory or start/restart the target.
Permissions remain governed by Linux; do not automatically elevate privileges
or change host policy when an access check fails.

## L1 validation and integration

Use deterministic public fixtures and a controlled synthetic Linux process.
That fixture may grant the test reader access to its own memory; the product
must not change another process's ptrace policy as part of attachment.

Acceptance covers:

- maps/stat parsing, unusual path/comm spelling, malformed/overflowing metadata
  and absent/duplicate mapping flags;
- identity changes, process exit and image mismatch;
- PIE and non-PIE VA/file/live translation, segment permissions, file-backed
  boundaries and ambiguous or unmapped addresses;
- known patterns, multiple hits, alignment, chunk boundaries, unreadable gaps,
  deduplication and compact window truncation;
- byte/result/output/time stop reporting and permission failures;
- existing static CLI/MCP behavior and an explicit unsupported-platform result.

Run only new/directly affected tests during implementation. Follow the repository's
final formatting/lint/compile gate and reuse successful checks on unchanged code.
Independent review must inspect the actual diff and evidence, not just an exit code.

## L2: bounded uprobe hit counts, caller evidence and register samples

Stage L2 (`probe`) command shape:

```sh
xref live probe --pid PID ADDR... [--backend perf|tracefs] [--count] [--callers] [--regs] [--duration-ms 1000] [--max-events 4096] [--json]
xref live probe --backend tracefs --pid PID ADDR... --fetch 'amount=+0x30(%rcx):u64' --filter 'amount > 0' --every 2 --first 64 --until-hits 128 --json
xref live probe --backend tracefs --pid PID ADDR... --duration-ms 0 --heartbeat-ms 1000 --group-by ret --mark-file /tmp/app.log --mark-regex '^TX-[0-9]+'
```

- **Target verification:** requires a verified `(dev, ino)` executable match and
  resolved PIE slide (`--force-bin` mismatches cannot install verified uprobes),
  an executable file-backed `PT_LOAD` (`PF_X`) offset, and an `iced-x86`-verified
  instruction boundary inside a known FDE/symbol anchor.
- **Primary backend (`--backend perf`, default):** opens per-TID dynamic uprobe
  PMU counters (`/sys/bus/event_source/devices/uprobe/type`) via `perf_event_open`
  with an `mmap` circular binary ring buffer (`PERF_RECORD_SAMPLE`,
  `PERF_RECORD_LOST`, `PERF_RECORD_FORK`), `mm`-filtered (`pid_isolated_breakpoint:
  true`) to the target process, dynamically attaching newly spawned threads and
  automatically releasing kernel probes when `xref` closes its file descriptors.
- **Explicit `tracefs` adapter (`--backend tracefs`):** uses an isolated instance
  under `instances/xref_<pid>_<nonce>` (`pid_isolated_breakpoint: false` because
  inode-wide `int3` traps fire across processes sharing the inode before tracefs
  filtering), two-pass `/proc/<pid>/task` seeding, `event-fork` + `record-tgid`,
  explicit exclusion of `fork` descendants (other TGIDs), `O_NONBLOCK`
  `trace_pipe` draining, `per_cpu/cpu*/stats` loss summation (`overrun`, `commit
  overrun`, `dropped events`, or `unknown`), FD-close-before-`rmdir` teardown,
  append-only `-:group/event` unregistration, and a `process_group(0)`-isolated
  parent-pipe cleanup supervisor subprocess so foreground process-group `SIGINT`
  (`Ctrl-C`), `SIGTERM`, or `abort` cleans up dynamic events.
- **Tracefs fetch and sampling options:** repeat `--fetch NAME=EXPR` up to 16 times
  (bounded register or nested memory fetches such as `amount=+0x30(%rcx):u64`).
  `--filter FIELD OP INTEGER` accepts only numeric comparisons over fetched values
  or fields enabled by `--regs`; the predicate is installed in the tracefs event and
  checked again while reading. `--every N` selects every Nth matching event per probe,
  `--first N` caps recorded hits per probe, and `--until-hits N` stops after N accepted
  hits across the session. These options require the explicit `--backend tracefs`;
  fetched values print beside register samples and appear in JSON `fetched_samples`.
  Sampling counts are marked as lower bounds; stored fetch output is capped and reports truncation.
  When multiple addresses are probed, fetch lines include the static probe VA prefix (`va 0x... fetch ts=...`),
  while single-probe sessions preserve the compact `fetch ts=...` format. Fetch labels accept register names
  when not conflicting with `--regs` or fetch syntax; reserved names (`reserved: ra`) are rejected with clear diagnostics.
- **Unbounded probing and heartbeats:** `--duration-ms 0` enables unbounded mode, running until `--until-hits`,
  target process exit, or `SIGINT`/`SIGTERM` (`Ctrl-C`). The first signal ends the observation and still prints the
  report and `--group-by` histogram; a second signal exits immediately, and the tracefs watchdog removes the probes.
  Optional `--heartbeat-ms N`
  periodically prints status to `stderr` with total hits collected, target liveness, and elapsed time since the last hit.
  In unbounded mode with `--json` and `--backend tracefs`, each hit is streamed immediately as a single-line JSON
  object (`va`, `tid`, `fetch`, and `ret` when known). The perf backend prints the final aggregated JSON report instead.
- **Caller grouping:** `--group-by ret` aggregates hits into a histogram keyed by caller return site (`[rsp]` static VA,
  symbolized with function names), summarizing fetched values per group.
- **Mark file tracking:** `--mark-file PATH --mark-regex RE` tails a log or state file without polling loops or `inotify`,
  stamping each probe hit with the latest matching line (e.g. current transaction ID or span). `RE` supports literals,
  `.`, `[...]`/`[^...]`, `\d \w \s` (and `\D \W \S`), `^`, `$` and the `* + ?` quantifiers; alternation, groups and
  `{n}` repetition are rejected with an error rather than silently matching nothing. The mark is the latest matching
  line visible when xref processes the hit, not one time-aligned with the uprobe: a line written between the hit and
  its processing (tracefs buffers events) can be attached to that hit. Use it to place hits in coarse progress
  (block height, phase), not to order events that are microseconds apart. tracefs backend only, together with
  `--fetch` or `--regs` (marks are stored on the captured samples).
- A full `probe_ready` receipt is emitted once. Later thread changes are compact
  `tid_attached`/`tid_observed` stderr records; JSON stores them in the separate
  `observation.thread_changes` array (`attached` for perf, `observed` for tracefs).
- **Capability matrix & zero silent fallback:** JSON and table outputs report a
  shared `capabilities` block (`requested`, `available`, `collected`, `detail`
  for `hit_counts`, `timestamp_ns`, `tgid_tid`, `callers`, `registers`, and
  `pid_isolated_breakpoint`), `truncated_by_max_events`, and
  `raw_register_bits_do_not_prove_source_types`. Neither backend ever silently
  falls back to the other on `EACCES`/`EPERM`.
- **Unwind & caller attribution:** evaluates the effective `CIE + FDE` unwind row
  at the probe PC (`CFA == RSP + 8` and `RA == Offset(-8)` at standard entries, or
  explicit RSP/RBP frame offsets), attributes callers via `return_static_va - 1`,
  and verifies the preceding `CALL` instruction with `iced-x86`, preserving raw
  return addresses and explicit tail-call/unwind caveats.

## L3: bounded hardware data watchpoints (`DR0`–`DR3`) and dependent watches (`--follow`)

Stage L3 hardware watchpoint command shape:

```sh
xref live watch --pid PID [ADDR...] [--follow SPEC]... [--len 1|2|4|8] [--access write|rw] [--regs] [--duration-ms 1000] [--max-events 4096] [--json]
```

- **Target validation (`1..=4` total hardware slots):** enforces the x86-64 `DR0`–`DR3`
  limit (`<= 4` hardware watchpoint slots per session across fixed `ADDR`s and
  `--follow` chains), natural alignment (`runtime_va % len == 0`
  for `len` in `1 | 2 | 4 | 8`), mapped region bounds, and writable permission
  for `--access write` (`rw-p`). Accepts either live runtime VAs (heap, stack,
  anonymous, or static data) or static ELF VAs mapped via PIE slide.
- **Dependent watch model (`--follow ptr_slot=<ADDR>[,offset=<OFF>][,len_slot=<ADDR>,min_len=<BYTES>][,guard_slot=<ADDR>,guard_val=<U64>][,header_ptr_slot=<ADDR>,header_offset=<OFF>]`):**
  - Reserves **2** hardware slots for a single-hop chain (`1` write watch on `ptr_slot`
    + `1` watch on the resolved leaf `*ptr_slot + offset`) or **3** hardware slots
    when `header_ptr_slot` is also watched (`total_slots <= 4`).
  - Re-evaluates the pointer chain via a bounded two-pass `/proc/<pid>/mem`
    consistency check (`MAX_REBIND_SNAPSHOT_RETRIES = 3`), never trusting a
    sample's `written_value` as a proven new pointer.
  - Records `rebind_events` across `initial_bind`, `in_place_resize`,
    `relocated_buffer` (disabling/closing old leaf `DR` samplers and opening new
    samplers at `generation + 1`), and disarmament (`disarmed_null_or_unmapped`,
    `disarmed_bounds_violation`, `disarmed_guard_mismatch`, `disarmed_torn_read`,
    `lost_header_binding`) so freed or reused heap allocations are not attributed
    to the disarmed watch.
  - Reports `rebind_coverage_gap: true`, `counts_are_lower_bound: true`, and
    `root_liveness` (`assumed_live_without_allocator_proof` or
    `guard_verified_without_allocator_proof`) with explicit caveat
    `leaf_rebind_uses_two_pass_proc_mem_read_never_sample_store_value_and_cannot_prove_allocator_lifetime_without_guard`.
- **Per-TID `PERF_TYPE_BREAKPOINT` + `PERF_SAMPLE_REGS_INTR`:** opens per-thread
  hardware breakpoint counters (`HW_BREAKPOINT_W` or `HW_BREAKPOINT_RW`) with
  `mmap` binary ring buffers, dynamically attaches newly spawned target TIDs via
  `PERF_RECORD_FORK` and `/proc/<pid>/task`, and automatically releases `DR0`–`DR3`
  when `xref` closes its file descriptors.
- **Post-execution `trap_ip` vs `candidate_writer_static_ip`:** x86-64 data
  watchpoints trap *after* the store/access instruction commits (`trap_ip` points
  to the next instruction). `xref` caches the decoded enclosing FDE layout on
  first hit (`WriterStaticCache`), rejects function/symbol boundaries, intra-FDE
  direct branch/call targets (`ambiguous_branch_target`), and non-fall-through
  predecessors (`Call`, `IndirectCall`, `UnconditionalBranch`, `IndirectBranch`,
  `Return`, `Exception`), verifies effective-address overlap against the watched
  range, and reports the local linear predecessor as a candidate
  (`candidate_linear_predecessor_store` or `candidate_linear_predecessor_read`)
  with the explicit caveat `candidate_linear_predecessor_store_operand_assumes_no_indirect_or_cross_fde_entry`.
- **Candidate store-operand value decoding vs memory snapshots:** decodes
  `written_value` as `candidate_register_store` (using the 16-GPR
  `PERF_SAMPLE_REGS_INTR` snapshot at trap delivery) or `candidate_immediate_store`
  for `mov [mem], reg` and `mov [mem], imm` instructions under the same explicit
  no-indirect-entry caveat; read-back from `/proc/<pid>/mem` before and after
  observation is reported separately as `initial_snapshot` / `latest_snapshot`
  with `latest_proc_mem_snapshot_not_store_time_value`.

## L4: opt-in PID-pinned live MCP tool (`xref_live`)

Stage L4 opt-in MCP startup command:

```sh
xref -b app.elf mcp --allow-live-pid PID
```

- **Strict opt-in & default isolation:** without `--allow-live-pid PID`,
  `xref -b app.elf mcp` exposes only the read-only `xref_query` tool (`readOnlyHint:
  true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint:
  false`), and any `tools/call` for `xref_live` is rejected with JSON-RPC
  `-32602` (`"unknown tool"`).
- **Startup identity pinning:** when `--allow-live-pid PID` is supplied, `xref`
  validates `PID != 0`, opens `/proc/<pid>` with `force_bin = false`, verifies
  `verified_build_id` or `verified_sha256` against `--bin`, and pins `(pid,
  starttime_ticks, exe_dev_ino)` in `LiveMcpContext`. If startup validation
  fails (dead PID, non-Linux host, Mach-O binary, or binary mismatch), the
  process exits nonzero before writing anything to `stdout`.
- **No PID/binary redirection & lifecycle safety:** `LiveQuery` (`maps`,
  `resolve`, `memscan`, `probe`, `watch`) uses `#[serde(deny_unknown_fields)]`
  and intentionally omits `pid`, `bin`, and `force_bin`. Every `xref_live`
  invocation re-verifies `starttime_ticks` and `exe_dev_ino` via
  `open_pinned_session`; if the pinned process exits or its PID is reused,
  `xref_live` fails with a structured `process_exited` or `process_changed`
  error (`isError: true`) while static `xref_query` calls remain available.
- **Tight MCP budgets, serialization & cooperative cancellation:**
  - Caps MCP `timeout_ms` / `duration_ms` at `1..=5000` ms, `max_hits` at
    `1..=64`, `max_bytes` at `1..=268435456` (256 MiB), `max_events` at
    `1..=4096`, `resolve` addresses at `1..=64`, `probe` addresses at `1..=16`,
    and total `watch` hardware slots (`addresses` + `follow`) at `1..=4` (`DR0`–`DR3`).
  - Serializes `xref_live` execution so at most **1** live operation runs at a
    time (returning `error.code == "busy"` on concurrent `xref_live` requests),
    while sharing the server's 2-request total admission cap and 64 KiB
    `MAX_RESPONSE_BYTES` response envelope (`LiveToolResponse`).
  - Honors `notifications/cancelled` and stdio EOF across `memscan`, `probe`,
    and `watch` loops (`ProbeStopReason::Interrupted`), ensuring immediate
    `perf` FD closure and `tracefs` teardown.

## Sampling profiles

On Linux x86-64, profile a verified executable and a running process with
hardware performance events. The kernel and system policy must permit the
requested events; unavailable events return an error rather than silently
changing the event or backend.

```sh
xref -b ./app live profile --pid "$PID" --duration 10s --freq 4000 \
  --callers dwarf --out capture.xprof
xref -b ./app profile report capture.xprof --by function --top 30
xref -b ./app profile report capture.xprof --by block
xref -b ./app profile report capture.xprof --by line
xref -b ./app profile annotate capture.xprof 0x1234 --json
xref -b ./app profile annotate capture.xprof 0x1234 --c
xref -b ./app profile diff before.xprof after.xprof --other ./app-new --json
xref -b ./app profile import perf.data --out imported.xprof --base 0x400000 --pid "$PID"
```

`--callers dwarf` unwinds a bounded captured user stack with CFI from the target
and verified shared objects; incomplete unwinds are reported and can omit
callers when a module or its CFI is unavailable. `fp`
uses kernel call chains, `lbr` needs supported hardware and provides a bounded
branch history, and `none` records leaf samples. Shared-library addresses are
attributed to their module when mappings are known; a file hash is a snapshot
of the backing file, not proof of unchanged in-memory code. Line reports need
DWARF line information; stripped images may leave samples unresolved. Pseudo-C
statement attribution is approximate and separately reports unmapped samples.

`--trigger-probe 0x1234 --window 200ms` uses a bounded in-memory flight
recorder around a uprobe hit. Thread attachment, buffer eviction and asynchronous
events can leave gaps; lost and dropped records, incomplete coverage, and the
trigger status are reported. The capture thread CPU measurement excludes costs
incurred by the target and interrupt contexts, so it is not a measurement of
the total workload slowdown. Sample shares are not exact execution time.

Importing text from `perf script`, or binary `perf.data` directly, currently
requires `--pid` and either a caller-supplied runtime
image `--base` or `--maps` snapshot. The base or snapshot and target identity
are unverified, mappings are synthetic,
and timestamps or event periods may be missing. Native import preserves recorded
sample periods, timestamps and loss records when present, but cannot prove the
target identity or recover all mappings. For recordings with multiple event types,
it imports the first and marks the report incomplete. It accepts bounded
zstd-compressed perf records, including bounded AUXTRACE records in compressed
streams. A supported Intel PT stream can be decoded from an AUX-only capture or
alongside one ordinary sampled event. Reconstructed instruction events are
reported separately from CPU samples: they do not measure elapsed time and have
no reconstructed timestamps. The importer requires a matching build ID and
executable mapping and currently rejects multi-thread or CPU-wide PT streams,
loss, unsupported packet sequences, and ambiguous image mappings. Other AUX
formats remain undecoded and mark a sample report incomplete; an unsupported
AUX-only capture cannot be profiled. Runtime code modifications cannot be ruled
out from perf metadata. The PT integration has been tested with synthetic trace
bytes, a compiled ELF and real perf sideband, not with a hardware Intel PT capture.
Mixed profiles currently support function, instruction, block, caller-path and
line reports; folded output, annotations and profile diffs reject them.
For this initial decoder, record a per-thread user-mode trace and restrict the
PT address filter to executable code in the selected target, for example:

```sh
perf record --per-thread -e intel_pt/mtc=0/u \
  --filter 'filter 0xSTART/0xSIZE@/path/to/target' -p "$PID" -- sleep 1
```

Replace `START` and `SIZE` with the file-relative executable range supported by
the host's perf address filter. CPU-wide streams, transitions outside the
verified target and unsupported packet sequences are rejected. Reaching the
instruction or callchain budget retains the decoded prefix and marks it as
incomplete with `intel_pt_instruction_budget_exhausted`.
Sample-READ records
with the basic grouped or single-value formats are accepted; their counter values
are not included in the profile. Unsupported READ format flags are rejected.
Compressed streams use a maximum 64 MiB zstd
window and each compressed record may expand to at most 64 MiB.
Input is limited to 16 GiB, feature metadata to 64 MiB and each perf event round
to 64 MiB or 131,072 records; exceeding a limit returns an error.
Native import first makes a private temporary copy of the input, so it needs
temporary disk space up to the input size and may take longer on large files.
Reports mark imports
incomplete rather than asserting equivalence with a native capture. For a
recording or snapshot made on a different system, use `--target-path` to identify
the target's original path.

Native perf imports can infer the target slide from initial executable MMAP2
records when `--base` and `--maps` are omitted. The target path and ELF segment
layout must match; if the binary was moved, a unique matching recorded build ID
can identify its original path. Ambiguous slides, paths or changed mapping
identities are rejected.
The recorded mappings and build ID cannot prove that runtime code bytes remained
unchanged. `profile report --within FUNCTION_OR_VA` keeps matching call chains;
`profile annotate --percent function --min-samples N` shows function-relative
shares and counts. `--hz`, `--duration-ms` and `--callgraph` are available on
`live profile`; `profile diff --by function --min-delta 0.5%` filters small
absolute changes in sample share.

For multiple post-trigger windows, use `--trigger-probe VA --window-ms 500
--max-windows 20`. Add `--trigger-fetch 'op=+40(%sp):u64' --trigger-filter
'op == 1'` to evaluate a named value captured by a tracefs uprobe at the hit.
The latter requires writable tracefs and perf tracepoint access. Report a single
window with `profile report FILE --window 1`, or their union without double
counting overlaps with `--merge-windows`; either can be combined with `--within`.
Multiple-window profiles use `.xprof` schema 3; this version continues to read
schema 1 and 2, while older versions cannot read schema 3.
Sampling is enabled only after the observer receives a matching trigger, so the
beginning of a window can be missed; profiles explicitly mark this coverage
limitation and report trigger losses. Trigger uprobes attach to threads found by
polling `/proc` every 25 ms, so a thread that starts, hits the trigger and exits
between two polls is not observed; such profiles carry the
`trigger_misses_threads_shorter_than_the_proc_poll_interval` warning, and
`trigger_not_observed` does not prove the trigger never ran. Existing centered single-trigger captures
remain available with the original `--window` option.

The existing opt-in `xref_live` MCP tool also accepts the `profile` operation
for the pinned process with the same 5-second duration and 4096-event caps.
Its capture buffer is bounded to 16 MiB and the existing response-size cap
applies.

## Primary references

- [Linux proc maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
  and [smaps flags](https://man7.org/linux/man-pages/man5/proc_pid_smaps.5.html).
- [Process-memory access](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
  and [Rust FileExt::read_at](https://doc.rust-lang.org/std/os/unix/fs/trait.FileExt.html#tymethod.read_at).
- [Kernel uprobes](https://docs.kernel.org/trace/uprobetracer.html) and
  [perf_event_open](https://man7.org/linux/man-pages/man2/perf_event_open.2.html).
- [bpftrace language](https://bpftrace.org/docs/release_026/language): the numeric
  uprobe form exists, but its exact address domain must be checked for the
  selected backend/version rather than assumed from another interface.
