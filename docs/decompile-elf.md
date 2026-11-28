# Decompile a stripped ELF binary to pseudo-C from the command line

How to decompile a stripped x86-64 ELF function to typed pseudo-C with xref: find it by a string or constant, read it as C, get JSON for scripts, or ask through a local MCP server. Recorded output and limits.

xref reads the executable itself: there is no project to create and no
analysis database to wait for. Each command loads the file, finds the
function ranges in its `.eh_frame` unwind table and answers. The examples
below run on the official ripgrep 14.1.1 release binary, which is stripped:
it has no symbols, so functions are named by address (`fn_1835f0`).

## 1. Find the function

A stripped binary has no function names, but it still has its strings and
constants. Start from text you can see the program print or accept. ripgrep
writes its statistics as JSON with the key `searches_with_match`:

<!-- xref:run -->
```console
$ xref -b rg refs searches_with_match
```

```text output
text 0x492c1a  "searches_with_match"
0x183676  in 0x1835f0  lea rsi, [0x492c1a]
0x1837d5  in 0x183750  lea rsi, [0x492c1a]
0x183a48  in 0x1838b0  movups xmm0, [0x492c1a]
0x183e4d  in 0x183dd0  lea rsi, [0x492c1a]
0x183f9e  in 0x183f20  lea rsi, [0x492c1a]
5 hits
```

```stderr
xref: load 2.2ms, total 6.6ms
```
<!-- /xref -->

Each line is an instruction that loads the string and the function it is in
(`in 0x1835f0`). For a number instead of text use [`imm`](cli/imm.md) or
[`callargs`](cli/callargs.md); to find functions by several properties at
once (strings, calls, size, source file) use [`find`](cli/find.md).

## 2. Decompile it

[`xref c`](cli/c.md) takes any address inside a function and prints the
whole function:

<!-- xref:run max=40 -->
```console
$ xref -b rg c 0x1835f0
```

```c output
/*
 * fn_1835f0 — 0x1835f0..0x18374c (348 bytes, 1 direct caller; synthetic FDE entry)
 *   params:
 *     arg_0 (rdi): unk64 — 64-bit register (signedness unconstrained)
 *     arg_1 (rsi): void * — dereferenced by store
 *   return: unk64 in rax (consumed by 1/1 direct call site)
 */
unk64 fn_1835f0(unk64 arg_0, void *arg_1) {
  void *ptr_1 = arg_1; /* rsi */
  void *slot_0; /* [rsp+0x0], addr-taken */
  u32 slot_8; /* [rsp+0x8] */

  void *ptr_2 = *(u64 *)(ptr_1);
  *(u64 *)(ptr_1 + 24) = (*(u64 *)(ptr_1 + 24) + 1);
  *(u8 *)(ptr_1 + 32) = 0;
  usize v_3 = *(u64 *)(ptr_2 + 24);
  if (*(u64 *)(ptr_2 + 8) == v_3) {
    void *v_5 = ptr_1;
    /* fn_80aa0: calls fn_12a6d0, fn_99217 */
    fn_80aa0(ptr_2 + 8, v_3, 1, 1, 1);
    ptr_1 = v_5;
    v_3 = *(u64 *)(ptr_2 + 24);
  }
  ((u8 *)*(u64 *)(ptr_2 + 16))[v_3] = 123;
  *(u64 *)(ptr_2 + 24) = (v_3 + 1);
  *(u64 *)(ptr_2 + 32) = (*(u64 *)(ptr_2 + 32) + 1);
  slot_0 = ptr_1;
  slot_8 = 1;
  /* fn_15bf60: calls fn_46795d, fn_80aa0, fn_15f100 */
  /* &slot_0 passes the object stored above: slot_0 = ptr_1, slot_8 = 1 */
  unk64 v_4 = fn_15bf60(&slot_0, "elapsed", 7, arg_0 + 48);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */
  v_4 = fn_158e60(&slot_0, "searches", 8, arg_0);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */
```
*Output cut here: lines 1–40 of 67 shown.*

```stderr
xref: load 2.1ms, total 27.7ms
```
<!-- /xref -->

The header comment gives the range, the number of direct callers and the
inferred signature. String arguments appear as literals with their lengths,
and a comment above each call says what the callee calls in turn. The [`c`
page](cli/c.md) explains the rest of the output, field hints (`--fields`)
and how to print part of a function.

Several functions at once, each written to its own file in parallel:

<!-- xref:run -->
```console
$ xref -b rg c 0x1835f0 0x183750 0x1838b0 --out out
```

```c output
out/0x1835f0.c  2210 bytes  34.4ms
out/0x183750.c  2058 bytes  41.8ms
out/0x1838b0.c  8297 bytes  335.4ms
```

```stderr
xref: load 2.2ms, total 341.7ms
```
<!-- /xref -->

## 3. The same as JSON

[`xref query`](cli/query.md) answers one versioned JSON request. The `c`
operation returns the function range and the pseudo-C text, with a
confidence tier and an evidence id:

<!-- xref:run max=3 -->
```console
$ xref -b rg query '{"operation":"c","address":"0x1835f0"}'
```

```text output
{"build_revision":null,"confidence":"inferred","data":{"format":"pseudo_c","fragment":false,"function":{"end":"0x18374c","range_origin":"eh_frame_fde","rva":"0x1835f0","size_bytes":348,"start":"0x1835f0","symbol":null,"symbol_truncated":false},"kind":"text","text":"/*\n * fn_1835f0 — 0x1835f0..0x18374c (348 bytes, 1 direct caller; synthetic FDE entry)\n *   params:\n *     arg_0 (rdi): unk64 — 64-bit register (signedness unconstrained)\n *     arg_1 (rsi): void * — dereferenced by store\n *   return: unk64 in rax (consumed by 1/1 direct call site)\n */\nunk64 fn_1835f0(unk64 arg_0, void *arg_1) {\n  void *ptr_1 = arg_1; /* rsi */\n  void *slot_0; /* [rsp+0x0], addr-taken */\n  u32 slot_8; /* [rsp+0x8] */\n\n  void *ptr_2 = *(u64 *)(ptr_1);\n  *(u64 *)(ptr_1 + 24) = (*(u64 *)(ptr_1 + 24) + 1);\n  *(u8 *)(ptr_1 + 32) = 0;\n  usize v_3 = *(u64 *)(ptr_2 + 24);\n  if (*(u64 *)(ptr_2 + 8) == v_3) {\n    void *v_5 = ptr_1;\n    /* fn_80aa0: calls fn_12a6d0, fn_99217 */\n    fn_80aa0(ptr_2 + 8, v_3, 1, 1, 1);\n    ptr_1 = v_5;\n    v_3 = *(u64 *)(ptr_2 + 24);\n  }\n  ((u8 *)*(u64 *)(ptr_2 + 16))[v_3] = 123;\n  *(u64 *)(ptr_2 + 24) = (v_3 + 1);\n  *(u64 *)(ptr_2 + 32) = (*(u64 *)(ptr_2 + 32) + 1);\n  slot_0 = ptr_1;\n  slot_8 = 1;\n  /* fn_15bf60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  /* &slot_0 passes the object stored above: slot_0 = ptr_1, slot_8 = 1 */\n  unk64 v_4 = fn_15bf60(&slot_0, \"elapsed\", 7, arg_0 + 48);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"searches\", 8, arg_0);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"searches_with_match\", 19, arg_0 + 8);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"bytes_searched\", 14, arg_0 + 16);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"bytes_printed\", 13, arg_0 + 24);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"matched_lines\", 13, arg_0 + 32);\n  if (v_4 != 0) {\n    return v_4;\n  }\n  /* fn_158e60: calls fn_46795d, fn_80aa0, fn_15f100 */\n  v_4 = fn_158e60(&slot_0, \"matches\", 7, (arg_0 + 40));\n  if (v_4 == 0) {\n    /* fn_187760: writes arg_0 (+0x18); calls fn_46795d, fn_80aa0 */\n    v_4 = fn_187760(slot_0, slot_8);\n  }\n  return v_4;\n}\n","total_bytes":2210},"error":null,"evidence_id":"ev_53c0f9f66eb9e9ee","image":{"architecture":"x86_64","base_address":"0x0","bytes":6597984,"format":"elf","rva_basis":"lowest_load_segment_va","sha256":"f401154e2393f9002ac77e419f9ee5521c18f4f8cd3e32293972f493ba06fce7"},"operation":"c","page":{"complete":true,"next_offset":null,"offset":0,"returned":2210,"unit":"utf8_bytes"},"schema_version":1,"tool":"xref","tool_version":"0.7.0","untrusted_binary_content":true,"warnings":["heuristic_reconstruction","fde_range_is_not_source_function","cancellation_between_render_phases"]}
```
<!-- /xref -->

## 4. From an agent over MCP

`xref mcp` serves the same operations as a local stdio MCP server for one
selected binary. It exposes one read-only tool, `xref_query`, whose
argument is the same request object:

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

```json
{"name":"xref_query","arguments":{"request":{"operation":"c","address":"0x1835f0"}}}
```

Lifecycle, response shapes and limits:
[Structured queries and local MCP](mcp.md).

## Limits

- x86-64 only: ELF, and thin x86-64 Mach-O. arm64 Mach-O is read only for its
  symbols, and there is no 32-bit x86, ARM or PE support.
- One function at a time from an address you choose, not a whole-program C
  file. Function ranges come from `.eh_frame`; where it is missing, ranges
  are recovered from code spans and are less exact.
- The output is pseudo-C for reading, not source that recompiles. Types are
  what the machine code constrains (`void *` when dereferenced, `unk64` when
  nothing is known), not the original Rust, C or C++ types.

## Other command-line decompilers

- **Ghidra headless** (`analyzeHeadless`) imports a binary into a Ghidra
  project, runs Ghidra's auto-analysis and then runs the scripts you name;
  pseudo-C comes from a script that calls Ghidra's decompiler. It suits work
  that needs Ghidra's many processor languages or the same project in the
  Ghidra GUI later.
- **RetDec** (`retdec-decompiler`) decompiles a whole program to a C file. It
  reads ELF, PE, Mach-O, COFF and raw machine code for x86, x86-64, ARM,
  ARM64, MIPS, PIC32 and PowerPC. Its repository says it is in limited
  maintenance mode.

xref fits when the target is x86-64, you want one function's pseudo-C in
the shell or in a script without creating a project, and you want to find
that function from its strings and constants first.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.7.0 (the remapped release build of commit db9b69e, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
