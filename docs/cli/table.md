# xref table

Fixed-size records from an address, each 8-byte field with what fills it: a relocated pointer to a function, an import or data, or the file's bytes.

A Rust trait object calls a method through its vtable: `call [rax+0x30]`, with `rax` set to the address of one of several constant records on each branch. In a position-independent binary the function pointers in those records are 0 in the file, and the loader fills them from `R_X86_64_RELATIVE` relocations. `table` dumps such records with the relocations applied. `calls` and `c` resolve the call itself: when every path into it sets the register to one of known records, they list each possible target, with the condition of the branch that chose it when that is a plain `cmp x, imm; je`.

## Usage

<!-- xref:usage table -->
```text
xref table [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options table -->
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### A Rust vtable

<!-- xref:run max=20 -->
```console
$ xref -b xref.stripped table 0x1d9fe8 --stride 0x40
```
<!-- /xref -->

`+0x00` is `drop_in_place` (none here), `+0x08` and `+0x10` are the type's size and alignment, and the method pointers start at `+0x18`. Each `->` is a pointer the file stores as 0 and a relocation fills.

### The calls through it

<!-- xref:run max=12 -->
```console
$ xref -b xref.stripped calls 0x1426e0
```
<!-- /xref -->

`-> {…} via N records +0x30` lists the targets of an indirect call whose pointer is read at `+0x30` of one of `N` records. A method that several records share is listed once.

## Reading the output

- `record I at A` starts record `I`, at `A + I * stride`.
- `+0xNN  -> T` is a field filled by a relocation: a pointer to `T`, described like a call target (a function, an address inside one, or a PLT import). `-> name (import)` is an imported symbol's slot.
- `+0xNN  V` is a field the file stores as is, as a little-endian 64-bit value.
- In `calls` and `c`, `(when edi == 3)` is the condition under which the record holding that target is chosen: the block that takes its address is entered only through the taken side of a `cmp edi, 3; je`, or by falling through a `cmp edi, 3; jne`. A target without one is reached by several paths, or by a test that is not a comparison with a constant.

## Limits

- A record address is followed through register copies, `[rsp+d]` slots, and a function pointer loaded from it (`mov rcx, [rax+0x18]; call rcx`). One chosen in another function and passed in, or one loaded out of a table indexed at run time, is not followed.
- The conditions are named by the registers of the comparison in the assembly (`eax`), not by the pseudo-C variables.
- `--stride` must be a multiple of 8. A record whose fields are not 8-byte aligned is dumped 8 bytes at a time anyway.

## Provenance

<!-- xref:provenance -->
<!-- /xref -->
