# Walkthrough: from serialized keys to field offsets and writers (`xref field`)

This walkthrough runs the published **xref 0.4.0** on a **synthetic test
program** whose source is in this repository, so every answer can be checked
against the source. It shows the whole `xref field` path: from keys a program
emits, to the function that emits them, the offset of each field, the
instructions that prove it, and the ranked candidates for the code that writes
those fields.

The program is not a real application. It is the small generator
[`tests/fixtures/field_perf/generate.py`](../../../tests/fixtures/field_perf/generate.py)
with `--functions 2000 --writers`: one structure, one serializer, one real
writer, and 2,000 decoy functions that write the same offsets.

Everything below is copied from [`transcript.txt`](transcript.txt) (commands,
stdout, stderr, exit codes) and [`environment.txt`](environment.txt)
(identities). [`capture.sh`](capture.sh) reproduces both on Linux x86-64.

No run replays a stored report (`XREF_NO_RESULT_CACHE=1`) or asks a background
daemon (`XREF_NO_DAEMON=1`). Every run marked *cold* in the transcript starts
with its own empty cache directory; one run, marked *index reuse*, reuses the
index built by the cold run before it (see [Step 4](#step-4-a-second-query-on-the-built-index)).

**Inputs `field` accepts in 0.4.0.** `field` has no format-specific gate: it
runs on every input xref loads, that is x86-64 ELF executables and shared
objects and, since v0.2.0, thin little-endian x86-64 Mach-O images with DWARF
`__eh_frame`. Its key/value model follows x86-64 System V integer arguments.
The test suite and this walkthrough cover ELF only; `field` has no Mach-O test.

## The program

[`target.c`](target.c), as generated:

```c
#include <stdint.h>
struct record { uint64_t c, m, e; };
volatile uint64_t sink;
__attribute__((noinline, noipa)) void emit(const char *key, uint64_t length, const uint64_t *value) {
    sink ^= (uint64_t)key[0] + length + *value;
}
__attribute__((noinline)) void serializer(struct record *p) {
    emit("c", 1, &p->c); emit("m", 1, &p->m); emit("e", 1, &p->e);
}
__attribute__((noinline)) void writer(struct record *p, uint64_t value) {
    p->m += value; p->e ^= value;
}
int main(void) { struct record p = {1, 2, 3}; writer(&p, 4); serializer(&p); return (int)sink; }
```

`serializer` passes each key, its length and the address of the field to
`emit`, the way serialization code passes a key and a value. Plus a separate
assembly file with 2,000 functions `fixture_N`, each doing
`movq %rsi, 8(%rdi); xorq %rdx, 16(%rdi); ret`: decoys that write the same two
offsets as `writer` but are never called.

**Expected answer** (from the source and the symbols of the unstripped build):

| What | Expected |
| --- | --- |
| Function that emits `c`, `m`, `e` | `serializer` at `0x11c0` |
| Offsets | `c` +0x0, `m` +0x8, `e` +0x10 (three `uint64_t`) |
| Real writer of `m` and `e` | `writer` at `0x1210`, called once from `main` (`0x1050`) |
| Decoys | 2,000 functions writing +0x8 and +0x10, no callers |

The analysis runs on the **stripped** build (`objcopy --strip-all`, 0 symbols);
the symbols of the unstripped build are used only to check the answer.

## Step 1: the binary

```console
$ xref -b target-stripped stats
functions 2007  code 0x13cf6f bytes
largest 0x13dde4..0x13e06d (0x289 bytes)
pointers 3  imports 6  symbols 0
panic locations 0  source files 0
```

2,007 functions from `.eh_frame` (the 2,000 decoys plus the C functions and
runtime glue), no symbols.

## Step 2: keys to layout

Ask for the exact set of keys the program emits:

```console
$ xref -b target-stripped field --keys c,m,e --layout-only
"c,m,e": 1 layout candidates, 0 accessor candidates; candidates
key diagnostics: min-matches=3 max-functions=4096 max-instructions=4096 incomplete=false budget-exhausted=false
  key "c": refs=["0x11c0"] emissions=["0x11c0"]
  key "m": refs=["0x11c0"] emissions=["0x11c0"]
  key "e": refs=["0x11c0"] emissions=["0x11c0"]
layout 0: 0x11c0..0x1204 base=rdi input_relative_key_value_candidate addressed-span>=0x18 exact-size=unknown
  matched keys: ["c", "m", "e"]; missing keys: []
  order: lexical_call_site_order_not_source_declaration_or_runtime_order
  "c" -> 0x0 instruction-read-widths=[8]
    key 0x13f004 len=1 via rdi value=rdx (input_address_argument)
      key_value_call 0x11c0 0x11d7 -> call 0x11a0
  "m" -> 0x8 instruction-read-widths=[8]
    key 0x13f006 len=1 via rdi value=rdx (input_address_argument)
      key_value_call 0x11c0 0x11ec -> call 0x11a0
  "e" -> 0x10 instruction-read-widths=[8]
    key 0x13f008 len=1 via rdi value=rdx (input_address_argument)
      key_value_call 0x11c0 0x1202 -> jmp short 0x11a0
```

(Caveat, coverage and limitation lines follow; see the transcript.)

- **Where:** one layout, in the function `0x11c0..0x1204` = `serializer`.
  `base=rdi`: offsets are relative to the first argument on entry, `p`.
- **Offsets:** `c` → `0x0`, `m` → `0x8`, `e` → `0x10`, each read as 8 bytes.
  This matches `struct record { uint64_t c, m, e; }`.
- **Evidence** for each key: the key string's address and length go to `emit`
  in `rdi`/`rsi`, the field address in `rdx` (`via rdi value=rdx`), at the
  listed call instruction. The last call is a tail jump (`jmp short 0x11a0`).
- **Coverage:** `3 selected, 3 analyzed, 0 unsupported`: nothing was skipped.

Checked against the disassembly:

```console
$ xref -b target-stripped asm 0x11c0
function 0x11c0..0x1204
0x11c0  endbr64
0x11c4  push rbx
0x11c5  mov rdx, rdi
0x11c8  mov rbx, rdi
0x11cb  mov esi, 1
0x11d0  lea rdi, [0x13f004]
0x11d7  call 0x11a0                                      ; 0x11a0
0x11dc  lea rdx, [rbx+8]
0x11e0  mov esi, 1
0x11e5  lea rdi, [0x13f006]
0x11ec  call 0x11a0                                      ; 0x11a0
0x11f1  lea rdx, [rbx+0x10]
0x11f5  pop rbx
0x11f6  mov esi, 1
0x11fb  lea rdi, [0x13f008]
0x1202  jmp short 0x11a0                                 ; 0x11a0
```

`rdx = p` (`mov rdx, rdi`), `rdx = p + 8`, `rdx = p + 0x10` before the three
calls: exactly `&p->c`, `&p->m`, `&p->e`.

## Step 3: who writes the fields

Now search the whole binary for code that writes both `m` and `e` relative to
one pointer, ranked:

```console
$ xref -b target-stripped field --keys c,m,e --write --writes-all-of m,e --limit 5
```

The layout part is repeated; the writer candidates follow:

```text
accessor: 0x1210..0x121d base=rdi layout=0 matching-offsets=[8, 16] same_root_offset_constellation_not_type_proof
  rank: score=50 colocated-writes=2 callgraph-distance=Some(2)
  0x1214 +0x8 read_write width=8 add [rdi+8], rsi
  0x1218 +0x10 read_write width=8 xor [rdi+0x10], rsi
accessor: 0x121d..0x14a6 base=rdi layout=0 matching-offsets=[8, 16] same_root_offset_constellation_not_type_proof
  rank: score=40 colocated-writes=2 callgraph-distance=None
  0x121d +0x8 write width=8 mov [rdi+8], rsi
  0x1221 +0x10 read_write width=8 xor [rdi+0x10], rdx
accessor: 0x14a6..0x172f base=rdi layout=0 matching-offsets=[8, 16] same_root_offset_constellation_not_type_proof
  rank: score=40 colocated-writes=2 callgraph-distance=None
  0x14a6 +0x8 write width=8 mov [rdi+8], rsi
  0x14aa +0x10 read_write width=8 xor [rdi+0x10], rdx
accessor: 0x172f..0x19b8 base=rdi layout=0 matching-offsets=[8, 16] same_root_offset_constellation_not_type_proof
  rank: score=40 colocated-writes=2 callgraph-distance=None
  0x172f +0x8 write width=8 mov [rdi+8], rsi
  0x1733 +0x10 read_write width=8 xor [rdi+0x10], rdx
accessor: 0x19b8..0x1c41 base=rdi layout=0 matching-offsets=[8, 16] same_root_offset_constellation_not_type_proof
  rank: score=40 colocated-writes=2 callgraph-distance=None
  0x19b8 +0x8 write width=8 mov [rdi+8], rsi
  0x19bc +0x10 read_write width=8 xor [rdi+0x10], rdx
coverage: 2007 functions / 1298287 code bytes; 3 selected, 3 analyzed, 0 unsupported, 0 byte-budgeted, 0 instruction-budgeted, 2003 accessor functions checked
```

- **The real writer ranks first:** `0x1210` = `writer`, score 50. Its stores
  are `add [rdi+8], rsi` and `xor [rdi+0x10], rsi`: `p->m += value` and
  `p->e ^= value`.
- **Why it outranks the decoys:** all candidates write both offsets in one
  block (`colocated-writes=2`), but only `writer` is connected to the
  serializer through direct calls (`callgraph-distance=Some(2)`:
  `serializer` ← `main` → `writer`). The decoys have no callers
  (`callgraph-distance=None`). The `add` of `writer` also reads the field it
  writes (`read_write`), like an update, while a decoy overwrites `+0x8`
  (`write`).
- **What the ranking is not:** every row says
  `same_root_offset_constellation_not_type_proof`. The decoys write the same
  offsets and would be indistinguishable by offsets alone; the rank is a
  heuristic over instruction and call-graph evidence, not proof that a function
  handles a `struct record`. `2003 accessor functions checked`: the whole binary
  was scanned, not a sample.

Checked against the code and its callers:

```console
$ xref -b target-stripped asm 0x1210
function 0x1210..0x121d
0x1210  endbr64
0x1214  add [rdi+8], rsi
0x1218  xor [rdi+0x10], rsi
0x121c  ret
```

```console
$ xref -b target-stripped c 0x1210
/*
 * fn_1210 — 0x1210..0x121d (13 bytes, 1 direct caller; synthetic FDE entry)
 *   params:
 *     arg_0 (rdi): void * — writes +0x8 (8B), +0x10 (8B)
 *     arg_1 (rsi): unk64 — 64-bit register (signedness unconstrained)
 *   return: void (rax proven unread at 1 direct call site)
 */
void fn_1210(void *arg_0, unk64 arg_1) {
  *(u64 *)(arg_0 + 8) = (*(u64 *)(arg_0 + 8) + arg_1);
  *(u64 *)(arg_0 + 16) = (*(u64 *)(arg_0 + 16) ^ arg_1);
  return; /* callers ignore rax */
}
```

```console
$ xref -b target-stripped callers 0x1210
branches
0x1085  in 0x1050  call 0x1210
1 hits
address taken
0 hits
```

The pseudo-C is the source of `writer` line for line, and its only caller is
`main` (`0x1050`).

The same report is available as JSON (`--json`, the fifth command in the
transcript): `candidates[].fields[].emissions[].evidence_steps[]` for the
layout and `accessor_candidates[]` with `ranking_score`,
`colocated_written_fields` and `callgraph_distance` for the writers.

## Step 4: a second query on the built index

The cold `--write` run above stored an index of references, direct calls and
writer facts in its cache directory. A different query on the same binary
reuses it; here a writer filter that keeps only writes relative to an argument
register:

```console
$ xref -b target-stripped field --keys c,m,e --write --writes-all-of m,e --writer-root argument --limit 3 --json
```

The report's `coverage` shows the reuse: `"scan_index_cache_hits": 1` and
`"writer_index_cache_hits": 1` (both are `0` in the cold runs). The ranking is
the same (`0x1210` score 50, then decoys at 40): all candidates here write
through their first argument, so `--writer-root argument` removes none of them.
The stderr timing of this run is in the transcript next to the cold ones; it is
one run on a small input and says nothing about other binaries.

## Result

| What | Expected | xref 0.4.0 |
| --- | --- | --- |
| Emitting function | `serializer` `0x11c0` | layout 0 in `0x11c0..0x1204` |
| Offsets | `c` 0x0, `m` 0x8, `e` 0x10 | `c` 0x0, `m` 0x8, `e` 0x10 |
| Real writer | `writer` `0x1210` | first candidate, score 50 |
| Decoys | 2,000, no callers | score 40, `callgraph-distance=None` |

## Limits shown here

- The program is synthetic and small on purpose; it demonstrates the mechanism,
  not accuracy or speed on real applications. The timings on stderr in the
  transcript are single runs without result replay or daemon, each labelled
  *cold* (own empty cache) or *index reuse*; they describe this one input on
  this host only.
- `field` reports what the instructions show: offsets relative to the
  serializer's argument and writes relative to one pointer. It does not recover
  the type name, the structure size (`exact-size=unknown`) or the declaration
  order (`order: lexical_call_site_order…`).
- Writer ranking is a heuristic. Here the call graph separates the real writer;
  in a binary where decoys were also reachable, the scores would be closer.
  Check a candidate with `asm`, `c` and `callers`, as above.

## Identities

From [`environment.txt`](environment.txt):

- **xref:** 0.4.0 from the published archive
  `xref-v0.4.0-x86_64-unknown-linux-gnu.tar.gz` (SHA-256
  `15a32d4bbe59307709c058e6c6379d98814fcafe106d8edc0379165454edf0a2`), binary
  SHA-256 `5bca0429b1b283a9fb1e1b2357396e33681e583f4456d3fc9e6a76534a5d6463`,
  build revision `39997783594f5e8da910b1cc0e923b16c91738e8` (tag `v0.4.0`).
- **Generator:** `tests/fixtures/field_perf/generate.py` (MIT OR Apache-2.0),
  SHA-256 `3a56e0afe43e74ccc93b80ce4a050c53b2f74fccc1a8fa7ed02d490d1f3d1b04`,
  identical at tag `v0.4.0`; arguments `--functions 2000 --writers`.
- **Build:** `cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`,
  `-O2 -g0 -fno-inline -fno-ipa-icf`, then `objcopy --strip-all` from
  `GNU objcopy (GNU Binutils for Ubuntu) 2.42`.
- **Inputs:** `target.c` SHA-256
  `04ac2e10925081f363310d4379cca066e1001bd3d8eec2e8f9420c03a1f235b2`;
  stripped binary SHA-256
  `8eb4454ef7714df295c984225653249de68315631b3c00b63d2cdb5dd5037119` (identical
  across three builds). The unstripped binary is only used for its symbols; its
  SHA-256 differed between builds and is recorded for this run in
  `environment.txt` (`3a9236751e1103ed9e40e366990a4df3fe0550eef0caee940f7ac8ba8b2a7480`).
- **Host:** AMD Ryzen 9 9950X, Linux 6.8.0-111-generic x86_64; recorded
  2026-11-05 UTC.
