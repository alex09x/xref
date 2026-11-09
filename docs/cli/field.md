# xref field

Recover the in-memory layout behind serialized keys. Give `field` the keys a
program prints (JSON object keys, for example) and it finds the serializer code
that emits them, the offset of each field relative to the serialized value, and,
with `--write`, candidate code that writes those fields.

Use it on a stripped binary when you know what a structure looks like on the
wire and need to know where its fields live in memory: to read them with
[`xref live memscan`](https://github.com/alex09x/xref/blob/main/docs/live.md),
watch writes to them, or find the code that updates them.

## Usage

<!-- xref:usage field -->
```text
xref field [OPTIONS] [NAME]
```
<!-- /xref -->

Query one key (`NAME`) to see every layout that emits it, or an exact set of
sibling keys with `--keys a,b,c`.

## Arguments and options

<!-- xref:options field -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `[NAME]` | Single serialized key to query. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--keys <KEYS>` | Exact comma-separated set of sibling serialized keys (`--keys c,m,e`). |  |
| `--within <WITHIN>` | Only functions containing this address or symbol. |  |
| `--json` | Emit the structured report as JSON. |  |
| `--min-offsets <MIN_OFFSETS>` | Require this many distinct serialized offsets on the same input root in an accessor. | `2` |
| `--min-keys <MIN_KEYS>` | Accept a key-set candidate matching at least N requested keys; defaults to the full set. |  |
| `--exhaustive-key-seeds` | Include partial key-reference seeds even when no direct-call path combines them. |  |
| `--max-functions <MAX_FUNCTIONS>` | Maximum sibling helper functions selected into the discovery context (1..=8192). | `4096` |
| `--max-instructions <MAX_INSTRUCTIONS>` | Maximum decoded instructions per function for key/value analysis (1..=16384). | `4096` |
| `--write` | Show accessor instructions that may write the queried field. |  |
| `--writes-all-of <WRITES_ALL_OF>` | Require writes to every comma-separated field name. |  |
| `--writer-root <WRITER_ROOT>` | Only writers whose offsets are relative to this kind of pointer (`returned`: a pointer returned by a call, such as a map lookup). Values: `any` (Any root); `argument` (An ABI argument register on entry (`rdi`, `rsi`, …)); `returned` (A pointer returned by a call (`call lookup; mov r, rax; mov [r+off], …`)); `loaded` (A pointer loaded from memory (`mov r, [p+off]; mov [r+off], …`)). | `any` |
| `--limit <LIMIT>` | Maximum accessor rows (1..=128). | `64` |
| `--layout-only` | Skip the global accessor search while inspecting layout evidence. |  |
<!-- /xref -->

## Examples

The examples use the official ripgrep 14.1.1 release binary. With `--json`,
ripgrep ends a search with statistics such as:

```json
{"elapsed":{"secs":0,"nanos":143000,"human":"0.000143s"},"searches":2,"searches_with_match":1,
 "bytes_searched":4104,"bytes_printed":293,"matched_lines":3,"matches":3}
```

### One key: which layouts emit it

<!-- xref:run max=60 -->
```console
$ xref -b rg field searches --within 0x1835f0 --layout-only
```

```text output
"searches": 1 layout candidates, 0 accessor candidates; candidates
layout 0: 0x1835f0..0x18374c base=rdi input_relative_key_value_candidate addressed-span>=0x38 exact-size=unknown
  order: lexical_call_site_order_not_source_declaration_or_runtime_order
  "elapsed" -> 0x30 instruction-read-widths=[8]
    key 0x492c0b len=7 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x183644 -> call 0x15bf60
  "searches" -> 0x0 instruction-read-widths=[8]
    key 0x492c12 len=8 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x183664 -> call 0x158e60
  "searches_with_match" -> 0x8 instruction-read-widths=[8]
    key 0x492c1a len=19 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x183685 -> call 0x158e60
  "bytes_searched" -> 0x10 instruction-read-widths=[8]
    key 0x492c2d len=14 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x1836a6 -> call 0x158e60
  "bytes_printed" -> 0x18 instruction-read-widths=[8]
    key 0x492c3b len=13 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x1836c3 -> call 0x158e60
  "matched_lines" -> 0x20 instruction-read-widths=[8]
    key 0x492c48 len=13 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x1836e0 -> call 0x158e60
  "matches" -> 0x28 instruction-read-widths=[8]
    key 0x492c55 len=7 via rsi value=rcx (input_address_argument)
      key_value_call 0x1835f0 0x183700 -> call 0x158e60
  caveat: input_argument_relationship_not_concrete_rust_type
  caveat: minimum_extent_is_addressed_span_not_allocation_or_exact_type_size
  caveat: known_cfg_and_sysv_integer_argument_model
  caveat: nested_inline_sources_may_be_flattened
  caveat: stack_spills_assume_unmodelled_callee_writes_do_not_alias_private_slots
coverage: 446 functions / 291300 code bytes; 3 selected, 8 analyzed, 0 unsupported, 0 byte-budgeted, 0 instruction-budgeted, 0 accessor functions checked
limitation: key/value argument evidence is not proof of a Serde implementation or a concrete Rust type
limitation: offsets are relative to the displayed input argument in the displayed function
limitation: field order is lexical instruction evidence, not recovered declaration or universal runtime order
limitation: exact size, alignment, tail padding, skipped fields and allocator identity are unknown
limitation: only supported x86-64 SysV integer arguments and known static helper entry targets are summarized
limitation: opaque calls, erased or zero-sized values, scalar promotion and unsupported flows may have no candidate
limitation: accessors match a same-input-root offset constellation, not a proven common type; missing results do not prove absence
```

```stderr
xref: cached result, total 134.9µs
```
<!-- /xref -->

`--within 0x1835f0` limits the search to one function (found with
[`refs`](refs.md)); without it `field searches` reports every function that emits
the key (16 on this binary). `--layout-only` skips the writer search.

How to read it:

- `layout 0: 0x1835f0..0x18374c base=rdi` — the serializer function and the
  argument register its offsets are relative to: on entry `rdi` points to the
  serialized value.
- `"searches" -> 0x0`, `"searches_with_match" -> 0x8`, … `"elapsed" -> 0x30` —
  each emitted key and the offset of its value from `base`.
  `instruction-read-widths=[8]` is how many bytes the code reads there.
- `key 0x492c12 len=8 via rsi value=rcx` — the evidence: the key string address
  and length are passed in `rsi`/`rdx` and the field address in `rcx` to
  `call 0x158e60` at `0x183664` (`key_value_call`).
- `order: lexical_call_site_order…` — keys are listed in call order, which is not
  necessarily the declaration order.
- `caveat:`, `limitation:` and `coverage:` lines state what the result does not
  prove and how much of the binary was analysed.

So ripgrep's statistics structure keeps `searches` at `+0x0`,
`searches_with_match` at `+0x8`, `bytes_searched` at `+0x10`, `bytes_printed`
at `+0x18`, `matched_lines` at `+0x20`, `matches` at `+0x28` and `elapsed` at
`+0x30`, which matches the pseudo-C of the same function on the [`c`](c.md)
page.

### An exact set of keys

<!-- xref:run max=30 -->
```console
$ xref -b rg field --keys elapsed,searches,searches_with_match,bytes_searched,bytes_printed,matched_lines,matches --layout-only
```

```text output
"elapsed,searches,searches_with_match,bytes_searched,bytes_printed,matched_lines,matches": 8 layout candidates, 0 accessor candidates; candidates
key diagnostics: min-matches=7 max-functions=4096 max-instructions=4096 incomplete=true budget-exhausted=true
  key "elapsed": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"]
  key "searches": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
  key "searches_with_match": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
  key "bytes_searched": refs=["0x1835f0", "0x183750", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
  key "bytes_printed": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"]
  key "matched_lines": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"]
  key "matches": refs=["0x996fb", "0xd98e0", "0xda0a0", "0xdaa60", "0xdb420", "0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"]
  discovery limit: per_function_instruction_budget_exhausted
layout 0: 0x158d70..0x158e5c base=rcx input_relative_key_value_candidate addressed-span>=0x3c exact-size=unknown
  matched keys: ["elapsed", "searches", "searches_with_match", "bytes_searched", "bytes_printed", "matched_lines", "matches"]; missing keys: []
  order: lexical_call_site_order_not_source_declaration_or_runtime_order
  "elapsed" -> 0x30 instruction-read-widths=[8]
    key 0x492c0b len=7 via rsi value=rcx (input_address_argument)
      static_helper_argument_rebase 0x158d70 0x158dfb -> jmp 0x183f20
      key_value_call 0x183f20 0x183f6c -> call 0x1594c0
  "nanos" -> 0x38 instruction-read-widths=[4]
    key 0x492c75 len=5 via rsi value=rcx (stack_copy_of_input_scalar)
      static_helper_argument_rebase 0x158d70 0x158dfb -> jmp 0x183f20
      static_helper_argument_rebase 0x183f20 0x183f6c -> call 0x1594c0
      static_helper_argument_rebase 0x1594c0 0x15954b -> jmp 0x185630
      key_value_call 0x185630 0x1856af -> call 0x15a880
  "searches" -> 0x0 instruction-read-widths=[8]
    key 0x492c12 len=8 via rsi value=rcx (input_address_argument)
      static_helper_argument_rebase 0x158d70 0x158dfb -> jmp 0x183f20
      key_value_call 0x183f20 0x183f8c -> call 0x15d410
  "searches_with_match" -> 0x8 instruction-read-widths=[8]
    key 0x492c1a len=19 via rsi value=rcx (input_address_argument)
      static_helper_argument_rebase 0x158d70 0x158dfb -> jmp 0x183f20
```
*Output cut here: lines 1–30 of 323 shown.*

```stderr
xref: cached result, total 205.8µs
```
<!-- /xref -->

`--keys` asks for layouts that emit exactly these sibling keys. The `key
diagnostics` lines show, per key, the functions that reference the string
(`refs`) and those that emit it (`emissions`). The full output (cut above) lists
eight layouts: the four direct serializers at `0x1835f0`, `0x183750`,
`0x183dd0`, `0x183f20` (`base=rdi`) and four callers that reach them through a
helper (`base=rcx`).

`elapsed` is itself a structure (`secs`, `nanos`), so its own keys appear in the
layouts too (`"nanos" -> 0x38`). Keys inside a requested value do not count
against the exact set; in xref 0.4.0 they still did, and this
query returned no layout.

### A subset of keys

`--keys` is exact: a layout with more top-level keys than requested is not a
match.

<!-- xref:run max=12 -->
```console
$ xref -b rg field --keys searches,bytes_searched --layout-only
```

```text output
"searches,bytes_searched": 0 layout candidates, 0 accessor candidates; not_found_under_limits
key diagnostics: min-matches=2 max-functions=4096 max-instructions=4096 incomplete=true budget-exhausted=false
  key "searches": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
  key "bytes_searched": refs=["0x1835f0", "0x183750", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
coverage: 8345 functions / 4072139 code bytes; 127 selected, 141 analyzed, 6 unsupported, 0 byte-budgeted, 0 instruction-budgeted, 0 accessor functions checked
limitation: key/value argument evidence is not proof of a Serde implementation or a concrete Rust type
limitation: requested key set matches observed sibling emissions, not a source declaration
limitation: offsets are relative to the displayed input argument in the displayed function
limitation: field order is lexical instruction evidence, not recovered declaration or universal runtime order
limitation: exact size, alignment, tail padding, skipped fields and allocator identity are unknown
limitation: writer instructions are same-root offset witnesses, not proof of a common concrete type
warning: unsupported_cfg_or_instruction_budget_scopes_omitted
```

```stderr
xref: cached result, total 114.2µs
```
<!-- /xref -->

No layout emits only these two keys, so the result is empty. The status says
`not_found_under_limits` because some functions could not be fully analysed
(`warning: unsupported_cfg_or_instruction_budget_scopes_omitted`), not because
the budget was too small; raising `--max-instructions` would not help here.
To search by a subset, lower `--min-keys`:

<!-- xref:run max=12 -->
```console
$ xref -b rg field --keys searches,bytes_searched --min-keys 1 --layout-only
```

```text output
"searches,bytes_searched": 16 layout candidates, 0 accessor candidates; candidates
key diagnostics: min-matches=1 max-functions=4096 max-instructions=4096 incomplete=true budget-exhausted=false
  key "searches": refs=["0x1835f0", "0x183750", "0x1838b0", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
  key "bytes_searched": refs=["0x1835f0", "0x183750", "0x183dd0", "0x183f20"] emissions=["0x158760", "0x158850", "0x158bc0", "0x158d70", "0x15a120", "0x15c710", "0x15d650", "0x15e5e0", "0x1816e0", "0x181870", "0x181a80", "0x181c50", "0x1835f0", "0x183750", "0x183dd0", "0x183f20"]
layout 0: 0x158760..0x15884c base=rcx input_relative_key_value_candidate addressed-span>=0x48 exact-size=unknown
  matched keys: ["searches", "bytes_searched"]; missing keys: []
  order: lexical_call_site_order_not_source_declaration_or_runtime_order
  "binary_offset" -> 0x0 instruction-read-widths=[8]
    key 0x492bcb len=13 via rsi value=rcx (input_address_argument)
      static_helper_argument_rebase 0x158760 0x1587eb -> jmp 0x181a80
      key_value_call 0x181a80 0x181b88 -> call 0x159e80
  "stats" -> 0x10 instruction-read-widths=[8]
```
*Output cut here: lines 1–12 of 700 shown.*

```stderr
xref: cached result, total 244.3µs
```
<!-- /xref -->

`matched keys` and `missing keys` show how each layout relates to the request.
With `--min-keys 1` every layout that emits either key is listed, so expect many
candidates.

### Machine-readable output

<!-- xref:run max=45 -->
```console
$ xref -b rg field searches --within 0x1835f0 --layout-only --json
```

```json output
{
  "schema_version": 1,
  "queried_name": "searches",
  "image_sha256": "f401154e2393f9002ac77e419f9ee5521c18f4f8cd3e32293972f493ba06fce7",
  "status": "candidates",
  "ambiguous": false,
  "candidates": [
    {
      "function": "0x1835f0..0x18374c",
      "base_argument": "rdi",
      "fields": [
        {
          "name": "elapsed",
          "offset": 48,
          "offset_hex": "0x30",
          "instruction_read_widths": [
            8
          ],
          "emissions": [
            {
              "key_address": "0x492c0b",
              "key_length": 7,
              "key_argument": "rsi",
              "value_argument": "rcx",
              "evidence_steps": [
                {
                  "function": "0x1835f0",
                  "instruction": "0x183644",
                  "assembly": "call 0x15bf60",
                  "target": "0x15bf60",
                  "role": "key_value_call"
                }
              ],
              "source": "input_address_argument",
              "state_identity": "same_call_arguments"
            }
          ]
        },
        {
          "name": "searches",
          "offset": 0,
          "offset_hex": "0x0",
          "instruction_read_widths": [
            8
          ],
```
*Output cut here: lines 1–45 of 254 shown.*

```stderr
xref: cached result, total 113.2µs
```
<!-- /xref -->

The JSON report (`schema_version: 1`) carries the same evidence:
`candidates[].fields[]` with `offset`, `instruction_read_widths` and
`emissions[].evidence_steps[]` (function, instruction, assembly, role), plus
`coverage`, `limitations` and, with `--write`, `accessor_candidates`. The MCP
server returns the same report for `{"operation": "field", ...}`.

### Candidate writers

<!-- xref:run max=60 from="^accessor" -->
```console
$ xref -b rg field --keys elapsed,searches,searches_with_match,bytes_searched,bytes_printed,matched_lines,matches --write --writes-all-of searches,matched_lines --limit 3
```

*First 314 lines omitted; shown from the first line matching `^accessor`.*

```text output
accessor: 0x3a6e50..0x3a7e09 base=rdi layout=0 matching-offsets=[0, 8, 16, 24, 32, 40, 48, 56] same_root_offset_constellation_not_type_proof
  rank: score=72 colocated-writes=2 callgraph-distance=3
  score: colocated 16 + precise 16 + covered 32 + update 0 + conditional 0 + callgraph 8 = 72
  lead: +2 over 0x2464e0..0x2466b5 (callgraph +2)
  0x3a71da +0x0 write width=8 mov [rbx], r13
  0x3a7335 +0x0 write width=8 mov [rbx], r15
  0x3a7616 +0x0 write width=8 mov [rbx], r14
  0x3a7b1c +0x20 write width=8 mov [rbx+0x20], rbp
  0x3a7b5d +0x0 write width=8 mov [rbx], rax
  0x3a71dd +0x8 write width=8 mov [rbx+8], r15
  0x3a71e1 +0x10 write width=8 mov [rbx+0x10], r13
  0x3a71e5 +0x18 write width=4 mov dword ptr [rbx+0x18], 0xa
  0x3a7338 +0x8 write width=8 mov [rbx+8], r13
  0x3a733c +0x10 write width=8 mov [rbx+0x10], r15
  0x3a7340 +0x18 write width=4 mov dword ptr [rbx+0x18], 0x1f
  0x3a7619 +0x8 write width=8 mov [rbx+8], r13
  0x3a761d +0x10 write width=8 mov [rbx+0x10], r14
  0x3a7b0d +0x8 write width=4 mov [rbx+8], r13d
  0x3a7b14 +0x10 write width=8 mov [rbx+0x10], rdi
  0x3a7b18 +0x18 write width=8 mov [rbx+0x18], r14
accessor: 0x3a6e50..0x3a7e09 base=rdi layout=1 matching-offsets=[0, 8, 16, 24, 32, 40, 48, 56] same_root_offset_constellation_not_type_proof
  rank: score=72 colocated-writes=2 callgraph-distance=3
  score: colocated 16 + precise 16 + covered 32 + update 0 + conditional 0 + callgraph 8 = 72
  lead: +2 over 0x2464e0..0x2466b5 (callgraph +2)
  0x3a71da +0x0 write width=8 mov [rbx], r13
  0x3a7335 +0x0 write width=8 mov [rbx], r15
  0x3a7616 +0x0 write width=8 mov [rbx], r14
  0x3a7b1c +0x20 write width=8 mov [rbx+0x20], rbp
  0x3a7b5d +0x0 write width=8 mov [rbx], rax
  0x3a71dd +0x8 write width=8 mov [rbx+8], r15
  0x3a71e1 +0x10 write width=8 mov [rbx+0x10], r13
  0x3a71e5 +0x18 write width=4 mov dword ptr [rbx+0x18], 0xa
  0x3a7338 +0x8 write width=8 mov [rbx+8], r13
  0x3a733c +0x10 write width=8 mov [rbx+0x10], r15
  0x3a7340 +0x18 write width=4 mov dword ptr [rbx+0x18], 0x1f
  0x3a7619 +0x8 write width=8 mov [rbx+8], r13
  0x3a761d +0x10 write width=8 mov [rbx+0x10], r14
  0x3a7b0d +0x8 write width=4 mov [rbx+8], r13d
  0x3a7b14 +0x10 write width=8 mov [rbx+0x10], rdi
  0x3a7b18 +0x18 write width=8 mov [rbx+0x18], r14
accessor: 0x3a6e50..0x3a7e09 base=rdi layout=2 matching-offsets=[0, 8, 16, 24, 32, 40, 48, 56] same_root_offset_constellation_not_type_proof
  rank: score=72 colocated-writes=2 callgraph-distance=3
  score: colocated 16 + precise 16 + covered 32 + update 0 + conditional 0 + callgraph 8 = 72
  lead: +2 over 0x2464e0..0x2466b5 (callgraph +2)
  0x3a71da +0x0 write width=8 mov [rbx], r13
  0x3a7335 +0x0 write width=8 mov [rbx], r15
  0x3a7616 +0x0 write width=8 mov [rbx], r14
  0x3a7b1c +0x20 write width=8 mov [rbx+0x20], rbp
  0x3a7b5d +0x0 write width=8 mov [rbx], rax
  0x3a71dd +0x8 write width=8 mov [rbx+8], r15
  0x3a71e1 +0x10 write width=8 mov [rbx+0x10], r13
  0x3a71e5 +0x18 write width=4 mov dword ptr [rbx+0x18], 0xa
  0x3a7338 +0x8 write width=8 mov [rbx+8], r13
  0x3a733c +0x10 write width=8 mov [rbx+0x10], r15
  0x3a7340 +0x18 write width=4 mov dword ptr [rbx+0x18], 0x1f
  0x3a7619 +0x8 write width=8 mov [rbx+8], r13
  0x3a761d +0x10 write width=8 mov [rbx+0x10], r14
  0x3a7b0d +0x8 write width=4 mov [rbx+8], r13d
  0x3a7b14 +0x10 write width=8 mov [rbx+0x10], rdi
  0x3a7b18 +0x18 write width=8 mov [rbx+0x18], r14
```
*Output cut here: lines 315–374 of 383 shown.*

```stderr
xref: cached result, total 196.6µs
```
<!-- /xref -->

With `--write`, `field` searches the whole binary for functions that write the
same offsets relative to one pointer, ranks them and prints up to `--limit`
(`accessor:` blocks, after the layouts). `--writes-all-of` keeps writers that
store every named field. Each `accessor` line shows the function, the base
register and the matching offsets, then three lines:
- `rank: score=… colocated-writes=… callgraph-distance=…`;
- `score:` with every term of the score, which add up to it;
- `lead:` with the gap to the next listed function and the terms it comes from.

A lead made of one term, such as `callgraph` alone, is thin: the runner-up is
equal on everything else. The terms are described in
[Serialized field search](../field-search.md). The lines after these are the
store instructions.

The same function is listed once per layout it matches (`layout=0`,
`layout=1`, …), so with eight layouts the three rows here are one function.
Read the result critically. Here the top candidate, `0x3a6e50`, writes offsets
`0x0`…`0x38` of some 64-byte structure, including immediate values (`mov dword
ptr [rbx+0x18], 0xa`) that do not look like statistics counters: an offset
pattern shared by many structures is not proof of the same type
(`same_root_offset_constellation_not_type_proof`). Its `lead` line says how
thin the rank is: `+2 over 0x2464e0..0x2466b5 (callgraph +2)`. The next
function scores the same on every instruction term and is one call edge
farther from the serializer. Check a candidate with [`c`](c.md) before
relying on it, look at the runner-up, or restrict the pointer kind with
`--writer-root returned|argument|loaded`.

## Performance and caching

A whole-image search builds an index of references, direct calls and writer
facts under `$XDG_CACHE_HOME/xref/field-index-v1` and reuses it for other keys.
An identical command on an unchanged binary replays the stored report; on Unix a
background `field-daemon` answers later queries for the same binary. Details:
[Field key search](../field-search.md).

## Limits

- Offsets are relative to the serialized value as passed to the serializer, not
  necessarily to the start of a heap allocation.
- Only the x86-64 SysV integer-argument call model and known helper entry points
  are followed; opaque calls and unusual code generation may hide a layout. An
  empty result is not proof that the structure does not exist.
- Writer ranking is a heuristic over offset patterns, not type proof.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
