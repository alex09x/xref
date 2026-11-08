# xref callargs

Every call site in the binary that passes a given constant as an argument, grouped by callee.

`xref args` lists the arguments at the call sites of a function you already know. `callargs` goes the other way. You know a value, such as an enum tag, a status or an error code, and you want the code that passes it. A producer often never stores such a value itself. It hands the value to a shared helper (`mov r9d, 0x27; call helper`), and the helper writes it. `callargs` scans every function for direct calls and tail jumps whose argument registers (`rdi`..`r9`) or stack slots hold the constant at the call. It groups the hits by callee and argument position. For each group it also lists the other constants that callee receives in the same position. A helper that receives 13, 15, 16 and 39 in one register is a status-taking helper, and it stands out.

## Usage

<!-- xref:usage callargs -->
```text
xref callargs [OPTIONS] <VALUE>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options callargs -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<VALUE>` | The constant (decimal or 0x hex), compared with the whole argument register or stack slot. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--arg <ARG>` | Only this argument: rdi, rsi, rdx, rcx, r8, r9 or stack0..stack7. |  |
| `--callee <CALLEE>` | Only calls to this function (address or symbol name). |  |
| `--limit <LIMIT>` | Call sites listed; every callee is summarized. | `100` |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### A constant passed in one register

<!-- xref:run max=40 -->
```console
$ xref -b rg callargs 0x2c --arg rdx
```

```text output
callee 0x4740a0  rdx: 1 of 523 call sites pass 0x2c; constants there: 0x1 ×15, 0x2 ×5, 0x3 ×6, 0x4 ×93, 0x5 ×44, 0x6 ×19, 0x7 ×20, 0x8 ×20, 0x9 ×16, 0xa ×19, 0xb ×16, 0xc ×28, 0xd ×23, 0xe ×27, 0xf ×14, 0x10 ×19, +18 more
  0x236abb  in 0x236880..0x236ad9  jump  rdx=0x2c
callee 0x477060  rdx: 1 of 2 call sites pass 0x2c; constants there: 0x28 ×1, 0x2c ×1
  0x47720d  in 0x477180..0x4772b1  call  rdx=0x2c  r8=0xc4  stack0=0x1c2
2 call sites pass 0x2c to 2 callee arguments
constants are those set in the call's straight-line run: mov reg, imm; xor reg, reg; copies of such registers; mov [rsp+8k], imm; push imm
```

```stderr
xref: load 2.5ms, total 8.6ms
```
<!-- /xref -->

`0x4740a0` receives 34 distinct constants in `rdx` across 523 call sites. That is a general helper taking a length or a code, and the one call passing `0x2c` is a tail jump from `0x236880`, the serde_json `ErrorCode` `Display` used in the [`origin`](origin.md) example. `0x477060` has two call sites, and the constants show both of them.

## Reading the output

- `callee F  R: K of N call sites pass V` is a group: K call sites pass V to F in argument R, out of the N call sites of F. `constants there` lists every constant F receives in R across those N sites, with counts: one value, or the whole set of statuses a helper takes.
- Groups whose callee receives the most distinct constants in that position come first.
- Each indented line is a call site: its address, the containing function, `call` or `jump` (a tail jump leaving the function), and every argument that holds a known constant there.
- The last lines count the call sites and the groups and say how many were not listed because of `--limit`.

## Limits

- A constant is known only when it is set in the call's straight-line run: `mov reg, imm`, `xor reg, reg`, a copy of such a register, `mov [rsp+8k], imm` or `push imm`. A value set before a branch that rejoins, or computed, is not seen. A call clobbers the volatile registers.
- The value is compared with the whole register or stack slot after the write: `mov r9d, 0xffffffff` holds `0xffffffff`, not `-1` as a 64-bit value.
- Only calls with a resolved target are searched: direct calls and jumps, and calls through a pointer slot of a known function. A call through a register is not.
- Stack slots are counted from the stack pointer at the call (`stack0` is `[rsp]`), for slots 0 to 7.

`xref origin` uses the same scan: a call passing an enum tag to a function that writes that argument into the tag is listed as an argument site.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
