# xref slice

Backward program slice: minimal pseudo-C statements and branches reaching a target address or text.

## Usage

<!-- xref:usage slice -->
```text
xref slice [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options slice -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | Function address or symbol name. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--to <TO>` | Target hex address, call name, field offset, or string substring inside the function. |  |
| `--to-field <FIELD>` | Target memory field: offset relative to a base register at an instruction address (`+0x10 of rax@0xVA`). |  |
| `--fields` | Rewrite raw pointer offsets as inferred `->f_<off>` field hints before slicing. |  |
| `--goto` | Keep residual labels and gotos in the sliced pseudo-C. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### To fn_160bb0

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped slice 0xc7d60 --to fn_160bb0
```

```text output
/* slice of 0xc7d60..0xc7fbf -> fn_160bb0 (37/131 lines) */
void fn_c7d60(void *arg_0, const void *arg_1, usize arg_2) {
  u8 slot_28; /* [rsp+0x28], addr-taken */
  usize slot_30; /* [rsp+0x30] */
  unk64 slot_40; /* [rsp+0x40], addr-taken */
  if (arg_2 == 0) {
    return; /* callers ignore rax */
  }
  const void *ptr_1 = arg_1;
  const void *v_2 = arg_1 + arg_2 * 24;
  void *v_4 = &slot_40;
  do {
    const u8 *ptr_6 = *(u64 *)(ptr_1 + 8);
    usize v_7 = *(u64 *)(ptr_1 + 16);
    /* fn_160550: source core/src/str/pattern.rs:1398; calls fn_1606e0, fn_160a43, fn_1605f8 */
    fn_160550(v_4, ptr_6, v_7, "goto L_", 7);
    /* fn_124d50: source core/src/str/pattern.rs:1131; calls fn_124e3a, fn_160bb0, fn_124e29 */
    fn_124d50(&slot_28, v_4);
    if (slot_28 != 0) {
      usize v_8 = slot_30;
      usize v_9 = (v_8 + 7);
      if (v_9 != 0) {
        if (v_9 < v_7) {
          if ((i8)((u8 *)ptr_6)[v_9] < -64) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        } else {
          if (v_9 != v_7) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        }
      }
    }
    ptr_1 = (ptr_1 + 24);
  } while (ptr_1 != v_2);
}
```

```stderr
xref: load 509.5µs, total 4.6ms
```
<!-- /xref -->

### To fn_160bb0 --fields

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped slice 0xc7d60 --to fn_160bb0 --fields
```

```text output
/* slice of 0xc7d60..0xc7fbf -> fn_160bb0 (37/132 lines) */
void fn_c7d60(void *arg_0, const void *arg_1, usize arg_2) {
  u8 slot_28; /* [rsp+0x28], addr-taken */
  usize slot_30; /* [rsp+0x30] */
  unk64 slot_40; /* [rsp+0x40], addr-taken */
  if (arg_2 == 0) {
    return; /* callers ignore rax */
  }
  const void *ptr_1 = arg_1;
  const void *v_2 = arg_1 + arg_2 * 24;
  void *v_4 = &slot_40;
  do {
    const u8 *ptr_6 = *(u64 *)(ptr_1 + 8);
    usize v_7 = *(u64 *)(ptr_1 + 16);
    /* fn_160550: source core/src/str/pattern.rs:1398; calls fn_1606e0, fn_160a43, fn_1605f8 */
    fn_160550(v_4, ptr_6, v_7, "goto L_", 7);
    /* fn_124d50: source core/src/str/pattern.rs:1131; calls fn_124e3a, fn_160bb0, fn_124e29 */
    fn_124d50(&slot_28, v_4);
    if (slot_28 != 0) {
      usize v_8 = slot_30;
      usize v_9 = (v_8 + 7);
      if (v_9 != 0) {
        if (v_9 < v_7) {
          if ((i8)((u8 *)ptr_6)[v_9] < -64) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        } else {
          if (v_9 != v_7) {
            /* fn_160bb0: noreturn; source core/src/str/mod.rs:486; calls fn_160bc0 */
            fn_160bb0(ptr_6, v_7, v_9, v_7, "src/loops.rs:45:36");
          }
        }
      }
    }
    ptr_1 = (ptr_1 + 24);
  } while (ptr_1 != v_2);
}
```

```stderr
xref: load 625.2µs, total 4.7ms
```
<!-- /xref -->

### To fn_124d50

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped slice 0xc7d60 --to fn_124d50
```

```text output
/* slice of 0xc7d60..0xc7fbf -> fn_124d50 (20/131 lines) */
void fn_c7d60(void *arg_0, const void *arg_1, usize arg_2) {
  u8 slot_28; /* [rsp+0x28], addr-taken */
  usize slot_30; /* [rsp+0x30] */
  unk64 slot_40; /* [rsp+0x40], addr-taken */
  if (arg_2 == 0) {
    return; /* callers ignore rax */
  }
  const void *ptr_1 = arg_1;
  const void *v_2 = arg_1 + arg_2 * 24;
  void *v_4 = &slot_40;
  do {
    const u8 *ptr_6 = *(u64 *)(ptr_1 + 8);
    usize v_7 = *(u64 *)(ptr_1 + 16);
    /* fn_160550: source core/src/str/pattern.rs:1398; calls fn_1606e0, fn_160a43, fn_1605f8 */
    fn_160550(v_4, ptr_6, v_7, "goto L_", 7);
    /* fn_124d50: source core/src/str/pattern.rs:1131; calls fn_124e3a, fn_160bb0, fn_124e29 */
    fn_124d50(&slot_28, v_4);
    ptr_1 = (ptr_1 + 24);
  } while (ptr_1 != v_2);
}
```

```stderr
xref: load 606.8µs, total 4.5ms
```
<!-- /xref -->

### To fn_fb8e0

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped slice 0x9a8a0 --to fn_fb8e0
```

```text output
/* slice of 0x9a8a0..0x9a97a -> fn_fb8e0 (23/64 lines) */
u8 fn_9a8a0(const void *arg_0, unk64 arg_1, unk64 arg_2) {
  usize v_1 = arg_1; /* rsi */
  const u8 *ptr_9; /* rax */
  unk64 slot_0; /* [rsp+0x0], addr-taken */
  unk64 slot_8; /* [rsp+0x8] */
  if (v_1 == 0) {
    ptr_9 = 0;
    return ptr_9;
  }
  if (((u64 *)*(u64 *)(arg_0))[v_1] != 1) {
    ptr_9 = 0;
    return ptr_9;
  }
  const void *ptr_3 = *(u64 *)(arg_0 + 24);
  unk64 v_4 = *(u64 *)(*(u64 *)(arg_0 + 16));
  if (v_1 == v_4 + 2) {
    usize v_5 = (v_4 + 1);
    unk64 v_8 = ((v_5 * 96) + *(u64 *)(ptr_3 + 8));
    slot_0 = 1;
    /* fn_fb8e0: calls fn_fb9c6, fn_fb920 */
    ptr_9 = fn_fb8e0(v_8, &slot_0);
  }
}
```

```stderr
xref: load 613.6µs, total 3.0ms
```
<!-- /xref -->

## Reading the output

- The header gives the function, the target and how many of the function's pseudo-C lines the slice keeps (`37/131 lines`).
- Only the statements and branch conditions that can affect reaching the target are kept; everything else is dropped.
- `--fields` adds field-offset hints as in [`c --fields`](c.md).

## Limits

- The slice is static and intraprocedural: effects of callees are summarized by their call, not followed.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
