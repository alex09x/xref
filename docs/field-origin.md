# Field-origin investigations

Available in source revisions after v0.1.0. The JSON CLI and the local MCP
`xref_query` tool share this operation. The inspected ELF is never executed.

```json
{
  "operation": "field_origin",
  "request": {
    "address": "0x1000",
    "register": "rdi",
    "offsets": ["0x18", "0x28"],
    "callees": true
  }
}
```

Replace the example address with a file-backed FDE returned for your image.
The selected register denotes its value at FDE entry, not a recovered source
parameter or a stack-frame layout. Accepted names are the existing layout
registers: rdi, rsi, rdx, rcx, r8, r9, rbx, rbp and r12 through r15.

## What the evidence means

`accesses` contains reachable machine memory operations whose effective address
is derived from the selected entry register under the declared static model.
Each row carries its displacement, width in bytes, instruction address/bytes,
alias-definition instructions and an optional `via` call hop. The `access` mode
is `read`, `write`, `read_write` or `address`; conditional accesses have a
separate flag. A compare reads memory; a read/modify/write operation has mode
`read_write`. Vector accesses retain their observed width. A LEA has mode
`address` and width zero,
rather than pretending to load the pointed-to value.

`calls` records values available in SysV integer argument-register candidates
at each relevant instruction. These are register facts, not recovered arity
or proof that every register is consumed by a callee. Each argument has one of:

- `base_address`: the selected entry value with zero displacement;
- `field_address`: an address relative to that entry value;
- `loaded_value`: an unmodified value read by a specific MOV instruction,
  with `load_address` and `load_width_bytes`.

A loaded pointer is not treated as the original base. Passing a base does not
prove that a particular field is forwarded. With `callees: true`, a known
callee entry can be inspected using the proven register/address relationship.
Only its actual memory instruction then provides evidence for an access at the
combined root-relative displacement. The `via` object preserves caller,
call-site, target, callee register and base displacement. Loaded-value
arguments do not start a pointee traversal.

For example, a call may receive root+0x10 while its callee accesses +0x8.
The resulting access is reported at root+0x18. Address-register candidates are
therefore retained even when their displacement does not match `offsets`;
`requested_offset_match` makes this explicit. Loaded-value arguments are
filtered to the requested offsets. With no offset filter this property is null.
Filters accept at most eight nonnegative hexadecimal offsets fitting i64.
Unfiltered evidence may also contain negative displacements, written as
`-0x...`. No object size, allocation bound or source-language type is inferred.

Calls include necessary direct-CFG guard edges and the instructions defining
their flags. Unknown control flow suppresses certified origins and guards;
an unreachable site is not reported as a witnessed call. Individual memory
rows describe possible reachable operations, not proof that a branch executed
on a particular runtime input. Root entry registers can alias in reality;
unproven memory/base relationships remain counted as unresolved.

## Keep hints separate from witnesses

`layout_hints` reuses the existing linear layout scanner for root offset,
width and stride candidates. Every row is explicitly tagged
`heuristic_path_insensitive_not_a_type_or_forwarding_proof`.
These hints are separate from CFG-derived instruction witnesses. They do not
establish that a field was passed through a call, nor recover a C/Rust struct.

The CFG facts currently propagate full-width register copies, simple
entry-relative LEA and ADD/SUB-immediate addresses, and plain 32/64-bit MOV
loads. Unsupported transformations, subword writes, dynamic indices, FS/GS
contributions, address-size-32 accesses, vector-value forwarding, stack-spill
aliases and arithmetic on loaded values become unknown. Implicit string memory
operands are counted as unresolved rather than emitted as certified accesses.
Different or missing
origins at joins are not conflated. The model assumes SysV volatile-register
clobbers and returning calls; exceptional unwinding and arbitrary indirect
targets remain outside it. Facts are relative to an FDE range, which may be
only part of a source-level function.

## Select a slice explicitly

Discovery does not render a slice. Copy a returned `calls[].selection` object
into the same request's `selection` field. It contains `image_sha256`,
`function` and `call_site`. A different image digest is rejected; a site not
reached by this bounded field investigation is not silently substituted.

The selected exact instruction is sliced by the existing renderer. The
`slice` evidence step carries typed text, warnings, errors and UTF-8 pagination.
If it is a fragment, continue with the ordinary `slice` operation, the selected
function/site and the returned byte offset. Selection can refer to a witnessed
root call or a call inside an admitted one-hop callee scope. Raw assembly is
also available through `asm` using the reported function/instruction addresses.

## Budgets and limitations

Defaults: 20 rows per access/call/hint list, four callee scopes, 32768 output
bytes, 4096 slice bytes. The `limits` object accepts `rows` 1..40,
`callees` 0..4, `output_bytes` 4096..48000 and `slice_bytes` 4..8192.
Callee analysis is one hop; distinct call sites/register mappings remain
separate scopes. Retained forwarding calls beyond that hop produce
`callee_depth_limit`; loaded-value pointees instead produce
`loaded_value_pointee_not_followed`. Unreachable instructions are excluded
from counters only when the CFG is complete; an unknown dispatch keeps the
potential instructions in scope. Each scope supports at most 32 KiB of code, 2048 decoded
instructions and 100000 dataflow work items. Definitions are capped at eight
per fact; guards use the existing bounded search and 96 inline evidence rows.

`stops`, `scope_errors`, `unresolved_memory_operands` and per-witness
`definitions_truncated` / `guards_complete` expose gaps. The serialized output
cap preserves admitted evidence. List limits do not provide an automatic page
cursor: narrow offsets, select a returned callee as a new root, or adjust
limits explicitly. `complete_under_model` is not a proof of global completeness
or absence of a relationship; inspect all per-witness flags too.
This operation does not answer an unknown business-flow entry-point question,
prove runtime ordering or establish that deferred work is absent.
