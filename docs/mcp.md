# Structured queries and local MCP

Available starting with v0.2.0. The published v0.1.0 binaries do not contain
these modes.

The same typed analysis interface serves one-shot JSON queries and a local
stdio MCP process. It reads a selected x86-64 ELF or supported thin Mach-O; it does not execute that
file. Existing human CLI commands keep their output format.

## JSON CLI

```sh
xref -b app.elf query '{"operation":"info"}'
xref -b app.elf query '{"operation":"strings","text":"needle"}'
xref -b app.elf query '{"operation":"refs","address":"0x1200"}'
xref -b app.elf query '{"operation":"calls","address":"0x1000"}'
xref -b app.elf query '{"operation":"slice","address":"0x1000","to":"0x1007"}'
```

These are request-shape examples; replace addresses with evidence returned for
your input. Each invocation writes one JSON response and exits nonzero for an
application error. Parse `error` before consuming `data`.

Every response includes `schema_version: 1`, tool/package version, optional
build revision, image identity, operation, data/error, warnings and pagination.
Image identity contains the SHA-256 of the exact loaded file bytes, size,
format, architecture and the image base used for RVAs: the lowest load-segment
VA for ELF, or `__TEXT.vmaddr` for supported Mach-O.
Addresses are hexadecimal strings, preserving all 64 bits in JSON clients.
They are static image virtual addresses; no runtime ASLR slide is inferred.

## MCP configuration

Start one process for one image:

```sh
xref -b app.elf mcp
```

For a client using the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "xref": {
      "command": "/absolute/path/to/xref",
      "args": ["-b", "/absolute/path/to/app.elf", "mcp"]
    }
  }
}
```

The server advertises the `2025-11-25` protocol and its initialization lifecycle:
`initialize`, `notifications/initialized`, then tool requests. It exposes one
read-only tool, `xref_query`, with generated input/output schemas. Its arguments
wrap the same query object used by the CLI:

```json
{"name":"xref_query","arguments":{"request":{"operation":"info"}}}
```

Analysis responses appear in `structuredContent` and as serialized JSON in a
text content block. Application failures set `isError: true`; malformed MCP
requests use JSON-RPC errors. Stdout carries only protocol frames; diagnostics
go to stderr. The current SDK's legacy client and its automatic fallback from
modern discovery are covered by a real subprocess integration test. A
discovery-only `2026-07-28` lifecycle is not implemented in this first version.

The image is an immutable snapshot loaded once at startup. File changes do not
silently replace it; restart the process to select new bytes. Tool arguments
cannot open other filesystem paths. Runtime dependencies do not include an
async runtime or MCP SDK; those are used only by the reference-client tests.

## Opt-in live process inspection (`--allow-live-pid`)

By default, `xref -b app.elf mcp` is strictly static and exposes only
`xref_query`. On Linux x86-64, you can explicitly bind the MCP server to one
verified running process at startup:

```sh
xref -b app.elf mcp --allow-live-pid 12345
```

When `--allow-live-pid <PID>` is provided:

- Startup verifies `PID != 0`, `/proc/<pid>/stat` `starttime_ticks`,
  `/proc/<pid>/exe` `(dev, ino)`, and binary identity (`verified_build_id` or
  `verified_sha256` against `-b app.elf`). Any mismatch or dead PID aborts
  startup before emitting protocol frames.
- `tools/list` exposes a second tool, `xref_live` (`readOnlyHint: false`,
  `destructiveHint: false`, `idempotentHint: false`, `openWorldHint: false`),
  wrapping `LiveQuery` (`maps`, `resolve`, `memscan`, `probe`, `watch`):

```json
{"name":"xref_live","arguments":{"request":{"operation":"maps"}}}
{"name":"xref_live","arguments":{"request":{"operation":"resolve","addresses":["0x555555555140"]}}}
{"name":"xref_live","arguments":{"request":{"operation":"memscan","values":["0x1122334455667788"],"max_hits":16,"timeout_ms":2000}}}
{"name":"xref_live","arguments":{"request":{"operation":"probe","addresses":["0x1140"],"callers":true,"regs":true,"duration_ms":1000}}}
{"name":"xref_live","arguments":{"request":{"operation":"watch","addresses":["0x7f0000001000"],"follow":["ptr_slot=0x7f0000002000,offset=16"],"duration_ms":1000}}}
{"name":"xref_live","arguments":{"request":{"operation":"profile","duration_ms":1000,"max_events":4096}}}
```

- Tool arguments cannot supply `pid`, `bin`, or `force_bin`
  (`deny_unknown_fields`). Every `xref_live` call re-checks the pinned
  `(pid, starttime_ticks, exe_dev_ino)` identity and fails with
  `error.code == "process_exited"` or `"process_changed"` if the target process
  exited or was replaced.
- At most one `xref_live` request runs at a time (`busy` on concurrent live
  calls), with MCP caps of `duration_ms` / `timeout_ms <= 5000`, `max_hits <=
  64`, `max_events <= 4096`, and `MAX_RESPONSE_BYTES` (64 KiB). See
  [Linux live analysis](live.md) for full `L1`–`L4` semantics and caveats.
- The [Live Analysis walkthrough](live-walkthrough.md) shows the same
  operations as recorded CLI runs against a stripped fixture process.

## Operations

| Operation | Required fields | Result |
|---|---|---|
| `info` | none | Counts of unwind ranges, segments, symbols, imports and pointers. |
| `strings` | `text` | Sorted virtual addresses of matching byte sequences. |
| `refs` | `address` | RIP-relative memory references and recognized one-hop pointer slots. Optional `back` is 0..64 bytes. Direct branch operands are excluded. |
| `function` | `address` | Covering unwind range, RVA, name hint and provenance. |
| `calls` | `address` | Instruction addresses, call kinds and known targets; unresolved indirect branches are reported separately. |
| `callers` | `address` | Known reverse call sites, caller FDEs and unresolved-edge counts. |
| `call_context` | `address`, `call_site` | Conservative argument-register candidates, guards and instruction evidence. |
| `investigate` | `request` | Bounded string/function discovery, graph traversal and an explicitly selected slice. |
| `field_origin` | `request` | Entry-relative field accesses, address versus loaded-value register origins and bounded one-hop callee evidence. |
| `asm` | `address` | Instruction bytes, addresses/RVAs, decoder validity and direct reference evidence. |
| `c` | `address` | Pseudo-C from the existing renderer. Optional `fields` and `keep_gotos`. |
| `slice` | `address`, `to` or `to_field` | A backward slice to an instruction, call, or memory field (`+0x10 of rax@0xVA`). Optional `fields` and `keep_gotos`. |
| `dependencies` | none | The embedded Rust (`.dep-v0`) or Go (`.go.buildinfo`) dependency manifest, paged. Optional `filter`. |
| `card` | `address` | The function card: inputs, return registers, field stores, callees, indirect and panic calls, exits. Each list is capped so that the card fits one response; `totals` gives the full counts and `truncated` says whether any list was cut. |
| `find` | one predicate | Functions matching `calls`, `refs`, `imm`, `disp`, `src`, `size`, `insn` or `class`, ranked by predicates met (`any` sets the minimum), paged. At most 32 predicates; texts are 1..256 bytes (`refs` 1..512) and a `refs` string may occur at most 4096 times. `imm` and `disp` take numbers or decimal / `0x` strings. |
| `layout` | `address` | Field offsets, widths and accesses through a pointer register (`reg`, default `rdi`); `callees` follows the pointer into callees. |
| `files` | none | Rust source files recovered from panic locations, with location counts. Optional `pattern`. |
| `where` | `pattern` | Functions referencing panic locations in matching files, optionally on one `line`. |
| `origin` | `request.target` | The [`xref origin`](cli/origin.md) report for an error message (or an address in its `Display` arm): stores of its enum tag, conversions, calls passing the tag and their guards. Optional `back`, `depth`, `limit`, `slice`, `arg_depth`. Paged text (`page.offset`/`limit` in UTF-8 bytes). |
| `callargs` | `request.value` | The [`xref callargs`](cli/callargs.md) report: call sites passing the constant (a number, or a decimal or `0x` string), grouped by callee. Optional `arg` (`rdi`..`r9`, `stack0`..`stack7`), `callee`, `limit`. Paged text. |
| `data` | `request.address`, `request.as` | The [`xref data`](cli/data.md) report: typed values (`u8`..`u64`, `i8`..`i64`, `f32`, `f64`, `bytes`, `str`) at a virtual address. Optional `count` (1..4096) and `max_len` (1..65536; `count * max_len` at most 2 MiB for `str`). Paged text. |

`info` also carries `triage`: language, stripped, toolchains, Build-ID, embedded
dependencies and ready-to-run `recommended_queries`. Every answer has a
`confidence` (`observed`, `derived` or `inferred`) and a deterministic
`evidence_id`. `xref mcp --compact` (or `XREF_MCP_COMPACT`) leaves `outputSchema`
out of `tools/list` and puts a one-line summary in `content[0].text` instead of
the JSON, which stays in `structuredContent`.

Per-function operations require a file-backed `.eh_frame` FDE range. Its
`range_origin` is `eh_frame_fde`: this is evidence for an unwind range, not proof
of a complete source-level function. This initial API does not expose the
human CLI's synthetic-span fallback. The loader requires parseable DWARF
unwind records. See [Mach-O inputs](macho.md) for bases, linkage and partial
coverage. Non-x86-64, big-endian and unsupported container variants are rejected.

[Bounded investigations](investigations.md) compose this workflow into discovery
and explicit selection, retaining alternative call sites and intermediate evidence.

[Field-origin investigations](field-origin.md) distinguish base/address/value
relationships and retain the memory instructions observed in known callees.

For individual queries, search the string, follow returned reference
rows to a function, inspect its calls/assembly, then slice to the selected
call-site instruction address. Use `calls[].address` for an exact site; a
callee target address may appear at multiple call sites. `slice.to` otherwise
uses the existing CLI matching rules for names/text/addresses. Inspect all
pages and resolve multiple candidates explicitly.

## Budgets, continuation and errors

- Images: at most 256 MiB of input bytes.
- Item pages: `"page":{"offset":0,"limit":20}`, limit 1..100, offset at most
  10000. Continue with `page.next_offset` using the same operation/arguments and
  image identity. Lists are sorted by VA or instruction address. At the maximum
  offset, remaining results produce `pagination_window_exhausted` with
  `complete: false` and no next offset; narrow the query instead of receiving
  an unusable continuation token.
- Text pages: `"page":{"offset":0,"limit":8192}`, limit 4..16384 UTF-8 bytes.
  Use the returned byte offset; arbitrary offsets inside a code point are
  rejected. A partial text payload has `fragment: true` and an explicit warning.
  Reassemble pages before treating it as the complete renderer output.
- Assembly/call ranges: at most 1 MiB. Pseudo-C/slices: at most 32 KiB of machine
  code and 2 MiB of generated text.
- Canonical analysis JSON: at most 64 KiB. Oversized results return
  `response_too_large`; reduce the page limit. The auxiliary pointer-slot list
  is capped at 100 with a truncation flag; reference rows remain paginated.
- Stdio input frames: 64 KiB; oversized frames are drained through the next
  newline before processing resumes. Output frames: 256 KiB, including protocol
  metadata and the compatibility text block.
- At most two analysis requests run at once. Additional requests get `busy`;
  there is no unbounded work queue. IDs of active requests cannot be reused.

`notifications/cancelled` signals a matching active query without producing a
notification response. Cancellation is cooperative: scans poll between chunks
or instructions, while existing decompilation/slicing phases finish before
the next check. A cancelled worker retains its concurrency slot until it ends.
EOF cancels remaining requests and joins their workers. This is not a hard
preemptive CPU or memory limit for the existing analysis algorithms.

Errors distinguish invalid requests/addresses/pages, unsupported or unreadable
images, missing/invalid unwind ranges, excessive function/output sizes, missing
slice targets and cancellation. Check warning codes: pseudo-C, field hints and
slices remain heuristic reconstructions. No unknown value is promoted to a
recovered source fact by the transport.

## Verification

Offline stack symbolization is also available through `xref_query` with
`operation: "symbolize"`. It accepts bounded inline stacks and the selected
image's runtime base, never an arbitrary filename or PID. See
[offline stacks and observed edges](trace-analysis.md) for request examples,
mapping assumptions and limits. The same guide distinguishes native-stack
integration fixtures from optional actual kernel perf recording.

`tests/mcp.rs` compiles a small redistributable Rust fixture as a stripped ELF,
then uses the official Rust MCP SDK as an actual child-process client. It
checks image digest, tool discovery, the string-to-slice chain, instruction
evidence, continuation, errors, and byte-for-byte CLI parity for pseudo-C and
slices. Additional wire tests check malformed/oversized frames, initialization,
notifications, stdout framing, shutdown and unsupported images.

The test logs startup-to-initialization, the query sequence through the slice,
and total verification time separately. These are observations for one small
fixture, not general performance comparisons. CI separately checks the runtime
at the declared Rust 1.88 minimum.

Protocol references: [lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools),
[cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation).
