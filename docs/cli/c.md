# xref c

Decompile functions to structured, typed pseudo-C. `c` lifts the machine code of
each function containing the given addresses: arguments, local variables, loops
and branches, calls with their constant arguments, and string literals.

Use it to read what a function does after you found it with [`refs`](refs.md),
`callers` or [`field`](field.md). Alias: `decomp`.

## Usage

<!-- xref:usage c -->
```text
xref c [OPTIONS] <ADDRS>...
```
<!-- /xref -->

Each address may point anywhere inside a function; the whole function (its exact
`.eh_frame` range) is decompiled.

## Arguments and options

<!-- xref:options c -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDRS>...` | Addresses inside the functions to decompile. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--from <FROM>` | First address to print. |  |
| `--to <TO>` | End address (exclusive). |  |
| `--out <OUT>` | Write each decompiled function to `<OUT>/<start>.c` in parallel and print path, size and elapsed time. |  |
| `--fields` | Rewrite raw pointer offsets as inferred `->f_<off>` field hints using layout recovery. |  |
| `--goto` | Keep residual labels and gotos instead of introducing skip flags; retain structured loops and branches. |  |
| `--only-paths-to <ADDR>` | Emit only basic blocks that can reach this instruction address. |  |
<!-- /xref -->

## Examples

The examples use the official ripgrep 14.1.1 release binary and its statistics
serializer at `0x1835f0` (see [`field`](field.md)).

### Decompile a function

<!-- xref:run max=80 -->
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
    /* fn_80aa0: calls fn_80b3b, fn_12a6d0 */
    fn_80aa0(ptr_2 + 8, v_3, 1, 1, 1);
    ptr_1 = v_5;
    v_3 = *(u64 *)(ptr_2 + 24);
  }
  ((u8 *)*(u64 *)(ptr_2 + 16))[v_3] = 123;
  *(u64 *)(ptr_2 + 24) = (v_3 + 1);
  *(u64 *)(ptr_2 + 32) = (*(u64 *)(ptr_2 + 32) + 1);
  slot_0 = ptr_1;
  slot_8 = 1;
  /* fn_15bf60: calls fn_15bfdc, fn_15c049, fn_80aa0 */
  /* &slot_0 passes the object stored above: slot_0 = ptr_1, slot_8 = 1 */
  unk64 v_4 = fn_15bf60(&slot_0, "elapsed", 7, arg_0 + 48);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches", 8, arg_0);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches_with_match", 19, arg_0 + 8);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "bytes_searched", 14, arg_0 + 16);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "bytes_printed", 13, arg_0 + 24);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "matched_lines", 13, arg_0 + 32);
  if (v_4 != 0) {
    return v_4;
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "matches", 7, (arg_0 + 40));
  if (v_4 == 0) {
    /* fn_187760: writes arg_0 (+0x18); calls fn_187806, fn_80aa0, fn_1877e0 */
    v_4 = fn_187760(slot_0, slot_8);
  }
  return v_4;
}
```

```stderr
xref: load 4.4ms, total 31.8ms
```
<!-- /xref -->

How to read it:

- The header comment gives the function range and size, how many direct callers
  it has, and the inferred signature: `arg_0 (rdi)`, `arg_1 (rsi)` with a type
  where the code constrains it (`void *` when it is dereferenced, `unk64` when
  nothing is known) and the return register.
- `ptr_*`, `v_*` are values held in registers; `slot_*` are stack slots
  (`addr-taken` when their address escapes, as `&slot_0` does here).
- A comment above each call names what the callee itself calls
  (`/* fn_158e60: calls fn_158eda, … */`), so you can tell helpers apart without
  opening them.
- String arguments are shown as literals with their length:
  `fn_158e60(&slot_0, "searches", 8, arg_0)` is a call
  `(state, key, key_len, &value)`. The pairs `"searches"`/`arg_0`,
  `"searches_with_match"`/`arg_0 + 8`, … give the field layout directly.
- `((u8 *)…)[v_3] = 123;` writes `{` (123) into an output buffer: this is a JSON
  writer opening an object.

### Field hints

<!-- xref:run max=14 -->
```console
$ xref -b rg c 0x1835f0 --fields
```

```c output
/* field offsets: arg_0 [+0x8:addr, +0x10:addr, +0x18:addr, +0x20:addr, +0x28:addr]; arg_1 [+0x0:u64, +0x18:u64, +0x20:u8] */
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
```
*Output cut here: lines 1–14 of 68 shown.*

```stderr
xref: load 2.2ms, total 31.7ms
```
<!-- /xref -->

`--fields` adds a first line summarising the offsets each pointer argument is
accessed at (`arg_0 [+0x8:addr, …]; arg_1 [+0x0:u64, +0x18:u64, +0x20:u8]`) and
rewrites dereferences as `->f_<offset>` hints where layout recovery is
confident. `addr` means only the field's address is taken (passed on), never
loaded, so this function's body is unchanged apart from the summary; in
functions that load and store fields the body shows `ptr->f_10` instead of
`*(u64 *)(ptr + 16)`.

### Part of a function

<!-- xref:run -->
```console
$ xref -b rg c 0x1835f0 --from 0x183644 --to 0x183690
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
  /* ... slice from 0x183644 (function starts at 0x1835f0) ... */
  unk64 v_8; /* rcx */
  unk64 v_9; /* rsi */
  unk64 v_10; /* rdi */
  u32 v_11; /* rdx */
  void *slot_0; /* [rsp+0x0], addr-taken */

  /* fn_15bf60: calls fn_15bfdc, fn_15c049, fn_80aa0 */
  unk64 v_4 = fn_15bf60(v_10, v_9, v_11, v_8);
  if (v_4 != 0) goto L_183717;
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches", 8, arg_0);
  if (v_4 != 0) goto L_183717;
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches_with_match", 19, arg_0 + 8);
  /* ... truncated at 0x183690 (function ends at 0x18374c) ... */
}
```

```stderr
xref: load 2.1ms, total 34.3ms
```
<!-- /xref -->

`--from`/`--to` print only the statements for that address range, marked with
`slice from … / truncated at …` comments. Registers live at the start of the
range appear as fresh variables (`v_8`, `v_10`).

### Only the paths that reach an instruction

<!-- xref:run max=80 -->
```console
$ xref -b rg c 0x1835f0 --only-paths-to 0x183685
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
    /* fn_80aa0: calls fn_80b3b, fn_12a6d0 */
    fn_80aa0(ptr_2 + 8, v_3, 1, 1, 1);
    ptr_1 = v_5;
    v_3 = *(u64 *)(ptr_2 + 24);
  }
  ((u8 *)*(u64 *)(ptr_2 + 16))[v_3] = 123;
  *(u64 *)(ptr_2 + 24) = (v_3 + 1);
  *(u64 *)(ptr_2 + 32) = (*(u64 *)(ptr_2 + 32) + 1);
  slot_0 = ptr_1;
  slot_8 = 1;
  /* fn_15bf60: calls fn_15bfdc, fn_15c049, fn_80aa0 */
  /* &slot_0 passes the object stored above: slot_0 = ptr_1, slot_8 = 1 */
  unk64 v_4 = fn_15bf60(&slot_0, "elapsed", 7, arg_0 + 48);
  if (v_4 != 0) {
    /* ... */
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches", 8, arg_0);
  if (v_4 != 0) {
    /* ... */
  }
  /* fn_158e60: calls fn_158eda, fn_158f46, fn_80aa0 */
  v_4 = fn_158e60(&slot_0, "searches_with_match", 19, arg_0 + 8); /* @xref_slice_target */
  /* ... */
}
```

```stderr
xref: load 2.1ms, total 38.7ms
```
<!-- /xref -->

`--only-paths-to ADDR` keeps only the basic blocks from which `ADDR` can be
reached, here the call that serializes `searches_with_match`. The target is
marked `/* @xref_slice_target */`, branches that cannot lead to it are reduced to
`/* ... */`, and everything after it is dropped, which makes long functions
readable when you care about one call.

### Several functions to files

<!-- xref:run -->
```console
$ xref -b rg c 0x1835f0 0x183750 --out out
```

```c output
out/0x1835f0.c  2221 bytes  29.8ms
out/0x183750.c  2053 bytes  46.6ms
```

```stderr
xref: load 2.2ms, total 51.1ms
```
<!-- /xref -->

With `--out DIR` each function goes to `DIR/<start>.c`, decompiled in parallel;
stdout lists the files, sizes and times. Without `--out`, several addresses are
printed one after another.

## Limits

- Types are inferred from how values are used, not recovered from debug
  information; `unk64` means the code does not constrain the type.
- Instructions the lifter does not model are kept as `/* 0xADDR: … */` assembly
  comments, never silently dropped. Cross-check critical code with `xref asm`.
- Control flow the structurer cannot express without `goto` uses skip flags;
  `--goto` keeps the original labels instead.
- A call that takes the address of a stack slot (`fn(&slot_130)`) may read more
  than that slot. When the statements right before the call store the slots
  after it, a comment above the call names them with the values they hold
  there: `/* &slot_130 passes the object stored above: slot_130 = slot_60,
  slot_140 = slot_70 */`. Two calls with the same `&slot_130` then show which
  object each one receives.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.5.0 (commit c5cf554, PR #189) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
