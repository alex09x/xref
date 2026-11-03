# Linux live analysis: implementation plan and acceptance contract

Status: agreed development plan for [issue #46](https://github.com/alex09x/xref/issues/46).
Published `v0.2.0` does not include these commands. Examples below describe
the proposed interface; each stage becomes available only after implementation
and independent review. No release date is promised.

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

Proposed command shapes:

```sh
xref live maps --pid PID --json
xref live resolve --pid PID --address LIVE_VA --json
xref -b app.elf live resolve --pid PID --address LIVE_VA --json
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

## L2/L3 adapter spikes and remaining capabilities

Before production integration, validate one narrow question per isolated spike:

1. **Probe attachment and count:** chosen backend/version, numeric address
   conventions, executable identity, PID/TID scope and exact expected fixture
   hit count over a bounded observation interval.
2. **Caller/register evidence:** validate entry ABI or CFA recovery. A cold/split
   FDE start is not automatically a real CALL entry, and a tail call preserves
   an earlier return address. Preserve unknown callers.
3. **Lifecycle and loss:** interruption, target exit, missing privileges,
   throttling/lost events and cleanup. Avoid persistent global trace events
   without an explicit ownership/recovery strategy. Zero observed hits is
   limited to the recorded interval and coverage.
4. **Watchpoints:** hardware/thread resources, trap IP versus candidate writer,
   and only the instruction forms for which a stored value can be proven.
   Post-state registers or later memory contents are not universal proof.

Measure observation overhead on the controlled fixture. No generic per-hit
latency or production-throughput guarantee is established by this plan.
Live MCP follows after reader isolation and cancellation are proven; it requires
an explicit PID-bound startup opt-in and separate live tool semantics.

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
