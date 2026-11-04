# Offline stacks and observed call evidence

`symbolize` maps addresses from a saved run onto the **selected executable**.
It never attaches to a running process. Frames in another executable, a shared
library, an ambiguous mapping, or a range without unwind information remain
explicitly unresolved. These commands require a build containing the analysis
workflow additions; the v0.3.0 release predates them.

```sh
# One leaf-first address stack per line; BASE is the runtime image base.
xref -b app symbolize --input addresses.txt --base 0x555555554000

# Use the original process's saved maps, including its original executable path.
xref -b app symbolize --input addresses.txt --maps saved.maps --target-path /opt/app

# Preserve perf PID/TID and mapping/task events when exporting a recording.
perf script -i perf.data --show-mmap-events --show-task-events --show-lost-events \
  -F comm,pid,tid,cpu,time,event,ip,sym,dso > stacks.perf.txt
xref -b app symbolize --format perf --input stacks.perf.txt --pid 1234 \
  --target-path /opt/app --build-id <HEX_BUILD_ID> --jsonl

# Root-first, semicolon-separated folded input with a positive sample count.
xref -b app symbolize --format folded --input stacks.folded --base 0x555555554000 \
  --folded --group-callers

# Count weighted samples by the immediate return-address call site.
xref -b app symbolize --format perf --input stacks.perf.txt --group-by caller \
  --target-path /opt/app
```

`--base` means the runtime address corresponding to the binary's lowest image
virtual address, rather than an arbitrary executable mapping. For a non-PIE
ELF whose lowest image VA is `0x400000`, the ordinary base is `0x400000`.
`--maps` and `--base` are mutually exclusive. MMAP/MMAP2 records select mappings
by an exact executable path or a matching build ID. The default path is the
canonical local `-b` path; use `--target-path` if the recorded process used a
different path. A recorded build-ID
mismatch is an error. A path, caller-supplied base, or saved maps without a
build ID is an assumption, reported as such. An imported file is not
authenticated evidence of how its producer ran.

`--kind auto` treats the leaf IP as an instruction address and ancestors as
return addresses. `--kind instruction`, `return-address`, `static`, or `symbol`
overrides that convention. A `fn_<hex>` token always denotes a static address
unless explicit symbol mode was requested. Folded input is root first; plain
address input is leaf first. Exact unique symbol names work in folded input;
duplicate or absent names remain unresolved. Function-plus-offset symbol
expressions are not inferred.

For return addresses, function containment uses `RA - 1`; the original RA is
preserved. A `call_site` is emitted only when a decoded CALL ends at exactly
that return address. This does not prove an immediate direct caller: tail
calls, inlining and incomplete unwinding still matter. Function ranges come
from FDEs. Optional source hints are nearby Rust panic-location references,
not recovered DWARF line tables or proof of the sampled source line.

`--jsonl` streams one object per stack, followed by a summary object. `--folded`
(`--collapse`) aggregates canonical function labels; `--group-callers` adds known call sites
to ancestor labels and keeps an explicit unknown-site label otherwise.
`--group-by caller` instead aggregates each sample once by its immediate
caller's exact known call site, regardless of deeper ancestors. A missing
immediate caller remains unknown; it is never replaced by a deeper frame.
Unresolved frames remain gaps. Headerless `perf script -F ip` output is also
accepted with `--format perf`, using blank lines as stack separators and an
explicit base/maps. Such input has no PID field and cannot be filtered by PID.

Input processing is streaming. Defaults are 2 GiB of input, 100,000 samples and
30 seconds; explicit ceilings are 8 GiB, one million samples and 600 seconds.
Lines are limited to 64 KiB and stacks to 256 frames. Process, thread, active
mapping, call-site, edge and folded-group tables have independent finite
limits. Exhaustion is an error or an explicit partial/truncated result;
unknown frames and lost records are counted. The timeout is cooperative
between reads/records, not a way to interrupt blocked stdin or filesystem I/O.
An input hash on a truncated result covers only the consumed prefix.

## Observed edges

```sh
xref -b app edges import --format perf --input stacks.perf.txt \
  --target-path /opt/app --pid 1234 --out observed.json
xref -b app callers 0x12340 --with-observed observed.json
xref -b app tree 0x12340 --callers --with-observed observed.json
xref -b app path 0x12000 0x12340 --with-observed observed.json
```

Import writes a versioned JSON store only to the explicit `--out` path and
refuses to replace an existing file. The store is tied to the selected
executable's SHA-256 and build ID; graph queries reject a store for different
bytes. No implicit index is created or loaded. Without `--with-observed`,
existing graph queries retain their static behavior.

An observed edge is an adjacency between two **resolved neighboring stack
frames**. Unknown/foreign frames are never bridged. Its count is a weighted
number of stack samples, not an invocation count. Repeated recursive frames
can contribute more than one adjacency in one sample. Output labels distinguish
`static`, `observed`, and `static+observed`; an unknown call site remains
unknown. A path containing observed adjacency need not be a chain of direct
CALL instructions. The observed path view returns one shortest evidence path.
Absence means not found in the selected static/imported subset.

## JSON and MCP

The read-only `xref_query` tool and JSON CLI accept bounded inline stacks:

```json
{"operation":"symbolize","request":{"stacks":[{"frames":["0x555555556001","0x555555556025"],"weight":1}],"base":"0x555555554000","frame_kind":"auto"}}
```

Limits are 64 stacks, 512 total frames, 256 frames per stack and 256 bytes per
token, plus the existing 64 KiB response ceiling. This operation accepts no
filename, PID, replacement binary, or arbitrary process-memory request.
Observed-store file writes are CLI-only and are not exported through the
read-only MCP tool.

## Verification

`trace_analysis_core` covers mapping identity, PID/TID/fork/exec transitions,
unknown gaps, exact CALL ends, limits and a 70,000-stack/1.4-million-frame input.
`trace_symbolize_e2e` compiles a native C PIE, captures real `backtrace(3)`
return addresses and maps, strips symbols, and checks CLI, JSON, observed
indirect edges and an actual MCP SDK client. Its perf-compatible fixture text
wraps those real addresses; it is not presented as a kernel perf recording.
The separately ignored `actual_perf_record_of_controlled_native_binary_imports_target_frames`
test performs a real own-process `perf record` when that tool and kernel
permissions are available. It changes no system tracing policy.
