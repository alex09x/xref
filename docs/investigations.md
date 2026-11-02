# Bounded investigations

Introduced after v0.1.0; build the source revision containing this feature.
The JSON CLI and the local MCP `xref_query` tool accept the same request.
The inspected file is read, never executed.

## Discover, then select

```json
{
  "operation": "investigate",
  "request": {
    "seed": {"kind": "text", "text": "invalid request"},
    "direction": "both",
    "limits": {"depth": 1, "functions": 8, "rows": 10}
  }
}
```

For a known entry range, use `"seed":{"kind":"function","address":"0x1000"}`.
Addresses here illustrate request shapes, not an address valid in your image.
Optional `callee` restricts returned call-site candidates to the FDE containing
that address; it does not prune the graph traversal.

Discovery composes typed `strings` -> `refs` -> FDE candidates -> `calls`
(and `callers` when requested). It returns every candidate admitted by the
limits. Two instructions calling the same target remain two candidates.
The `evidence` array records operation inputs, parent step IDs, typed results,
pagination, warnings and per-step errors. `string_matches` records the exact
matched byte range, not the bounds of an entire source string.
`ambiguities` identifies multiple matches/functions/call sites.
No pseudo-C or slice is generated during discovery.

Each call-site candidate carries a `selection` object with `image_sha256`,
`function` and `call_site`. Copy the whole object into the next request:

```json
{
  "operation": "investigate",
  "request": {
    "seed": {"kind": "function", "address": "0x1000"},
    "selection": {
      "image_sha256": "<digest returned by discovery>",
      "function": "0x1000",
      "call_site": "0x1011"
    }
  }
}
```

Use the same seed/traversal limits to reproduce the discovered scope, or narrow
to its returned function. A selection from different image bytes is rejected.
A selection not reached in this request is reported as
`selection_not_reached_under_limits`; no alternative is silently substituted.
Only an explicitly selected instruction triggers a slice. That slice reuses
the CLI renderer with its exact instruction-address target. Its evidence step
contains text pagination; follow up with the ordinary `slice` operation and
returned byte offset to retrieve further fragments.

## Call-site context and reverse calls

```json
{"operation":"call_context","address":"0x1000","call_site":"0x1011"}
```

The result includes instruction bytes/addresses, reaching definitions for the
six SysV integer argument-register candidates, and conditional edges necessary
to reach the site under the direct CFG model. Guards include the branch and
flag-definition instruction addresses; the result does not invent a source
predicate. Raw evidence remains available through `asm`.

Register candidates are not a recovered signature or proof of callee arity.
The conservative dataflow currently recognizes 32/64-bit immediate moves,
64-bit register copies, register-zeroing XOR and RIP-relative address-taking.
Memory loads, unsupported arithmetic and partial-register updates become
`unknown`. At joins, a value is retained only when every modeled incoming
path agrees. Definitions are capped at eight per register.
Calls clobber SysV volatile registers; continuation assumes a returning call.
Unknown control-flow edges suppress recovered values and make the context
incomplete; required guards are withheld when the CFG has unknown edges or
the site is unreachable from the FDE entry. Valid trap instructions and
resolved external tail jumps are modeled as terminating edges.
Exception unwinding, computed jump targets, stack arguments,
vector arguments and interprocedural return values are outside this model.
An entry-register value denotes the entry of an FDE range, not necessarily
the entry of a complete source function.

Contexts have at most 32 KiB code / 2048 instructions, 100000 dataflow work
items, 200000 guard-search items, 16 guards and 96 evidence instructions.
Budget/unknown-edge flags are explicit. Lists of definition addresses can
outlive the capped inline instruction evidence; retrieve those through `asm`.
A direct `call_context` query lets the caller inspect a candidate omitted by
the compound context budget.

```json
{"operation":"callers","address":"0x1100","page":{"limit":20}}
```

Reverse calls preserve each known call instruction and its caller FDE,
including recognized tail jumps and pointer-resolved calls. Target matching
uses the covering FDE; the original target address is retained. Unresolved
indirect edges, missing unwind ranges and scan limits prevent a negative
result from proving absence of a relationship.

## Limits and partial results

Defaults: depth 1, eight functions, 24 primitive steps, ten rows per list,
four call-site contexts, 32768 output bytes, 4096 slice bytes.
Allowed maxima: depth 3, 16 functions, 32 steps, 20 rows, eight contexts,
48000 output bytes and 8192 slice bytes. Set `contexts: 0` to skip automatic
contexts during discovery. An explicitly selected site still requests its
slice and context, in that order. Optional contexts follow selected work.
Traversal is breadth first with FDE deduplication; cycles are not expanded
repeatedly. Depth counts graph edges beyond every seed FDE. Even reverse-only
traversal enumerates calls inside discovered FDEs as selectable candidates.
The function limit caps queued FDE expansions; reverse-call rows retain their
exact call sites even if their caller cannot be queued or its first call page
omits that instruction. The independent context/step budgets still apply.

The compound request admits at most 100000 FDE ranges; text-seed reference
scans additionally admit 64 MiB of summed FDE range bytes. A known function seed
can traverse a local callee graph in a larger image without that whole-image
reference scan. Reverse-call scans independently cap decoded code at 64 MiB
and warn when ranges are skipped. These caps bound work; they do not measure
wall-clock latency. The loaded image and base API budgets still apply.
Results preserve admitted evidence when a step, function, row, context, depth
or serialized-output limit is reached. Continuation is explicit follow-up
queries or a narrowed investigation, rather than a hidden automatic scan.
Cancellation is checked between stages and during core scans; rendering
retains the existing between-phase cancellation behavior.

`stops` explains why the bounded request stopped. In particular,
`selection_required`, `not_found_under_limits`, `depth_limit` and
`row_or_text_limit` are not global claims about the binary. Inspect each
step's warnings, errors and pagination. Known direct graph edges do not
establish the absence of indirect calls or deferred work.

This interface supports collecting positive native evidence for a concrete
entry-point question. It does not identify an unknown entry by business
semantics, prove a field was forwarded because its base was forwarded, or
conclude that deferred work is absent because no immediate call was found.
