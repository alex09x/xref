# xref origin

From an error message to the code that builds it: the stores of the message's enum tag, with the conditions that guard each.

`xref error` stops at the `Display` arm that formats a message. `origin` goes on to the places that decide to return that error. The `Display` dispatch tells how the enum's tag is stored: its width, its offset and, for a niche-encoded enum, the bias between the tag and the jump-table index. From that, the variant's tag value is known, and every store of that value with that width is a candidate. Each candidate is shown with the pseudo-C conditions it runs under, which is where a limit or a threshold shows up.

## Usage

<!-- xref:usage origin -->
```text
xref origin [OPTIONS] <TARGET>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options origin -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<TARGET>` | Text (or part of it) the variant's message contains, or an address inside its `Display` arm. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--back <BACK>` | Also accept references this many bytes before the text (rustc format pieces start with a length byte). | `1` |
| `--depth <DEPTH>` | Conversion levels followed from the message's enum inward. | `3` |
| `--limit <LIMIT>` | Sites rendered with their guarding pseudo-C; the rest are listed. | `12` |
| `--slice` | Also print the backward slice of every rendered site. |  |
| `--arg-depth <ARG_DEPTH>` | Calls a tag passed as an argument is followed through after the function it is passed to. | `3` |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### A serde_json error code in ripgrep

`number out of range` is one arm of serde_json's `ErrorCode` `Display`, a `u64` tag at offset 0. The output lists the stores of tag 14 that match that layout, then the ones that do not.

<!-- xref:run max=60 -->
```console
$ xref -b rg origin "number out of range"
```

```text output
text 0x4b1ccb  "number out of range"
display 0x2368bf  in 0x236880  variant 14 (0xe)  table 0x4b1b04  tag u64 [rdi+0x0]
  8 stores of u64 0xe
  site 0x183ba2  in 0x1838b0  mov qword ptr [rsp+0x18], 0xe  [payload +0x28]
    | unk64 v_4 = fn_1703a0(&slot_8, "elapsed", 7, v_3);
    | if (v_4 == 0)
    > slot_18 = 14;
      slot_8 = v_2;
      slot_40 = *(u128 *)(&slot_10);
      slot_38 = 14;
      slot_50 = 2;
  site 0x183bbd  in 0x1838b0  mov qword ptr [rsp+0x38], 0xe  [payload +0x18]
    | unk64 v_4 = fn_1703a0(&slot_8, "elapsed", 7, v_3);
    | if (v_4 == 0)
    > slot_38 = 14;
      slot_50 = 2;
      slot_58 = 0;
      slot_60 = v_25;
      fn_1776b0(&slot_98, v_9, &slot_38, &slot_50);
  site 0x2324e3  in 0x232180  mov [rsp-0x78], rax  [payload +0x8]
    | else of if (arg_1 < 10)
    | else of if (arg_1 < 100)
    | else of if (arg_1 < 1000)
    | else of if (arg_1 < 0x2710)
    | else of if (arg_1 < 0x186a0)
    | if (arg_1 < 0xf4240)
    > slot_m78 = 14;
      slot_m7c = 0;
      slot_m80 = 0;
      slot_m70 = 0;
      slot_m68 = 0;
  site 0x3b23e5  in 0x3b2280  mov qword ptr [rsp], 0xe  [payload +0xd]
    | usize v_5 = (*(u64 *)(ptr_1) - 7);
    | if (v_5 > 4) { … return arg_0; }
    | switch (v_5)
    > slot_0 = 14;
      break;
  9 calls pass u64 0xe as an argument stored at the tag offset or into a stack object
  argument site 0x14d514  in 0x14d0e0  call 0x1475c0  [passed as rsi to 0x1475c0, stored by 0x99980 (passed on as r8 to 0x475f90, then as rsi) at 0x9998c `mov [rbp-0x10], rsi` into a stack object never read back there]
    | v_15 = 0x8000000000000001;
    | fn_14d9c0(&slot_c0, arg_1, arg_2);
    | if (v_1 == 0)
    | else of if (slot_c0 != v_15)
    > u8 v_71 = fn_1475c0("backreferences", 14, v_17, v_16);
      if (v_71 == 0) {
  argument site 0x1925af  in 0x1918d0  call 0x42de60  [passed as rdx to 0x42de60, stored by 0x46cd10 (passed on as rdx to 0x97fe0, then as rdx) at 0x46cdce `mov [rbp-0x38], r15` into a stack object never read back there]
    | unk64 v_43 = *(u64 *)(ptr_42);
    | if (v_8 != 1) { … goto L_19228b; }
    | switch (slot_98e)
    | if (slot_940 != 1)
    | if ((i64)(lhs_191f44 + 1) <= 0) { … unreachable(); }
    | else of if (v_43 != 0)
    > fn_42de60(&slot_4b0, "RUST_MIN_STACK", 14);
      if (slot_4b0 == v_41) {
  argument site 0x2b3f45  in 0x2b3cd0  call 0x42de60  [passed as rdx to 0x42de60, stored by 0x46cd10 (passed on as rdx to 0x97fe0, then as rdx) at 0x46cdce `mov [rbp-0x38], r15` into a stack object never read back there]
    > fn_42de60(&slot_70, "RUST_MIN_STACK", 14);
      void *v_21 = slot_70;
      if (v_21 == v_1) {
  argument site 0x2dee98  in 0x2dee00  call 0x42de60  [passed as rdx to 0x42de60, stored by 0x46cd10 (passed on as rdx to 0x97fe0, then as rdx) at 0x46cdce `mov [rbp-0x38], r15` into a stack object never read back there]
    > fn_42de60(&slot_f8, "RUST_MIN_STACK", 14);
```
*Output cut here: lines 1–60 of 96 shown.*

```stderr
xref: load 3.2ms, total 6.0s
```
<!-- /xref -->

This example also shows the limits of the method. A small tag value such as 14 is common, so some sites are stores of 14 that sit next to other data. Their guards show what they are: a lookup of a field named `"elapsed"`, a cascade of decimal-digit thresholds (number formatting). The argument sites are calls passing a string and its length (`"RUST_MIN_STACK", 14`): the callee, a few calls deeper, builds a `Vec` or a slice of that length on its stack and passes it on by pointer, which is the shape of a tag built into a stack object. A store is only a candidate. Its guards decide.

## Reading the output

- `text` lines give each place the message text occurs.
- `display` gives the `Display` arm that names the text: the function, the variant indices, the jump table, and the tag the table dispatches on (`tag u16 [rdi+0x0]`). A niche-encoded enum adds `= index + K, dataful index D`: the tag is the index plus K, and index D is the variant that holds the payload, which has no tag of its own. `tag load not found before dispatch` means the dispatch is not one of the recognised shapes (a plain load, or `sub rS,K; mov rI,D; cmovae rI,rS`), so nothing is searched.
- `N stores of u64 0xe` counts the stores of that value with that width, written directly or through a register loaded with the constant.
- `site` is a store with layout evidence. `[tag offset]` means it writes the tag's offset of an object that is not on the stack and has no index register. `[payload +N]` means a store to the same object, N bytes past the tag, is next to it. Layout cannot prove that the object is this enum, so a site is still a candidate.
- Lines starting with `|` are what decides that the store runs: the definitions of the innermost condition's operands, then the enclosing conditions and early exits on its path, outermost first. `else of if (c)` means the store is in the `else` branch. `if (c) { … return; }` is an early exit before the store.
- `>` is the store itself in the pseudo-C, and the indented lines after it are the statements that follow in the same block, usually the variant's payload.
- `argument site` is a call that passes the tag value in an argument register or stack slot to a function that writes that argument, with the tag's width, at the tag offset of an object that is not on the stack, or into an object it builds on its own stack: a frame slot it never reads back directly (so not a spill), at or above a frame address it passes to a call in an argument register (`lea rdi, [rsp+d]; call f`, or the source of a `memcpy`), so not an outgoing stack argument, and not a value whose address only goes into another stack structure (format arguments). The bracket says which argument, which function stores it, and the store: ``[passed as r9 to 0x11e0, stored by 0x11e0 at 0x11e7 `mov [rdi], r9b`]``. The value is followed through copies, including into callee-saved registers that survive calls, and through stack spills that are reloaded. When a function hands it on in an argument register, the next function is checked too, up to `--arg-depth` calls deeper, and the bracket gives the path: `stored by H (passed on as r9 to G, then as rsi)`. A function calling itself with the same argument is checked once. The guards are those of the call in its caller.
- When the stack object holding the tag is copied whole (a call to `memcpy`/`memmove`, or `rep movs`, with the object's frame address as the source and a constant size), the bracket goes on: `copied by memcpy at 0x133e to +0x40 of the object passed in rdi (0x200 bytes)`, or `to +0x110 of a 0x2c8-byte record` when the destination is computed (an element of a Vec). The indented `reader` lines under the site are the reads of the tag in the copy: after the copy in the same function, in the functions the copy is passed to, and, when the copy went into an object the function received, in its caller after the call. For a record, `N reads of +0x110 of 0x2c8-byte records` lists the reads of that field anywhere in the binary where the element address comes from the record size: an index scaled by it (`imul reg, x, 0x2c8`, or `shl` for a power of two), a pointer stepped by it in a loop, or such an address passed to a function. A reader that copies the record onto its own stack first (`lea rdi, [rsp+0x470]; mov rsi, element; mov edx, 0x2c8; call memcpy`), itself or in a function the element is passed to, is followed into that copy: its reads of `[rsp+0x470+field]`, or of the field through the copy's address passed on, are readers, and the bracket says `copy-in at 0x… to [rsp+0x470], field +0x110`. A loop that consumes the records by value is followed too. A pointer stepped by the record size may run one element ahead of the one it reads (`add rbx, 0x2c8` before the body, then `[rbx-0x1b8]` for +0x110) or start inside it (`lea rbx, [rdi+8]`), and a register set from it keeps the byte it points at, also into the arms of a jump table. A copy routine called through a register (`mov r15, [rip+memcpy@got]; call r15`) counts as a copy, and so does a copy of part of the element: `memcpy(&local, element + 8, 0x2c0)` holds +0x110 at `local + 0x108`. A copy of that copy on the same frame is followed (`, then copied at 0x… to [rsp+0x280]`), and so is a function handed the record rebuilt there or an address inside the copy before the field (an enum's payload). A 16- or 32-byte vector load that covers the field is listed with `a 16-byte load that covers it`: it moves the field with its neighbours rather than testing it.
- `stores without layout evidence` are listed after the sites as `candidate` lines. They may write an unrelated field that holds the same number.
- `argument candidate` lines are calls passing the tag value to a function that stores that argument with the tag's width into a field of an object at another offset. Calls reaching the same store share one line. A store into a frame slot that is read back is a spill and is ignored.
- `possible conversion` marks a site in a jump-table arm reached with no branch, in a function whose dispatch decodes to another tag. That is the shape of `From<Inner> for Outer` or a clone. The input variant is then traced the same way, up to `--depth` levels. When the input has the same tag value, width and offset, it is noted and not searched again.
- The last two lines count the sites, the stores without evidence, the argument sites and candidates and the possible conversions, and repeat that sites are candidates.

## Limits

- A tag passed as an argument is found when the constant is in an argument register or stack slot at the call ([`callargs`](callargs.md) has the rules) and the callee, or a function it passes the value on to in a register or stack slot (up to `--arg-depth` calls, 64 functions at most), stores it. Spills are followed through slots off `rsp` (while every path agrees on it) and off a frame pointer: `rbp` after `mov rbp, rsp`, or any register holding a frame address. Such slots survive an aligned `rsp` (`and rsp, -32`), and `leave` or `mov rsp, rbp` gives `rsp` back. A copy of a stack struct is followed when its size is a constant at the copy. An inline copy whose count is computed (head and tail moves around a `rep movsq`), a run of vector moves are not followed, and neither is a bulk copy of many records with a computed size (moving a whole buffer) before they are read. A tag passed in a stack argument slot (`stack0..stack7`, a constant `push` or `mov [rsp+8k], imm` before the call) is followed into the callee from its incoming slot, and so is a value the callee passes on in an outgoing slot; the bracket names it (`passed as stack1 to 0x1320`). `xref callargs` still finds the call that passes the constant.
- A tag written in a join block after a jump (`mov ecx, TAG; jmp join; … mov [m], rcx`) is not found.
- Small tag values are common, so the search finds many unrelated stores. Wider tags (`u16` variants of a large error enum) and payload stores make the sites more specific.
- The guards come from the pseudo-C, so they are only as good as its control-flow recovery. Only the six innermost conditions are shown. `--slice` prints the full backward slice of each rendered site, and `--limit` caps how many sites are rendered.
- The `Display` code must use a jump table. A variant mapped through `if` chains or a lookup table gives no variant index (as with `xref error`).

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
