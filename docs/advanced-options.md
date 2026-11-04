# Stack displacement searches and label-preserving output

Available starting with v0.2.0. The v0.1.0 binaries do not include these flags.

These options are useful when inspecting stack-resident output objects or long
functions whose residual control flow becomes difficult to follow after
structuring.

## Include stack accesses in a displacement search

```sh
xref -b app.elf disp 0x20 --stack
xref -b app.elf disp 0x20 --stack --write --in 0x1000
xref -b app.elf disp 0x20 0x28 --stack --all
xref -b app.elf disp 0x20 --stack --lea
```

`--stack` includes stack accesses alongside the normal displacement matches.
Matches based on `rsp`, and on `rbp` when the function has a recognized frame
pointer, carry a `; stack` annotation. A frame-less use of `rbp` remains an
ordinary base register. With `--all`, each function summary includes the number
of stack hits. The option works with `--write`, `--lea`, `--all`,
`--stride` and `--in`.

The query supports both literal frame displacements and offsets relative to an
explicit address-taken stack anchor. For example:

```asm
lea rdi, [rsp + 0x40]
call fill_output
mov rax, [rsp + 0x58]
mov rcx, [rsp + 0x68]
```

Here `disp 0x18 0x28 --stack --all` finds the two accesses relative to the
explicit anchor `rsp+0x40`. An individual match shows that anchor, the matched
field offset and the address of the instruction establishing the anchor.
`disp 0x58 --stack` still finds the literal frame displacement.

Stack-pointer changes are normalized to entry RSP coordinates. An anchor must
be established on every known incoming path before an access; conflicting or
unknown frame coordinates suppress relative matching while literal searches
remain available. Indexed LEA instructions do not establish constant anchors.
The address-forming LEA itself matches relative offset zero under `--lea`.

For relative `--all` matches, every requested offset must be supported by the
same normalized anchor. Offsets from different anchors are not combined to
claim one matching buffer. Multiple interpretations of an instruction do not
inflate instruction counts. Full anchor groups are ranked before raw matches.

An explicit address is evidence for an offset relationship, not proof of a
source-level structure, object bounds or a callee's writes. Anchor matches are
reported as candidates. This option does not infer aggregate types or sizes.

Negative frame displacements use the same 64-bit representation as other
displacement queries. For `[rbp - 0x20]`, use:

```sh
xref -b app.elf disp 0xffffffffffffffe0 --stack
```

`--stack` currently applies to `disp`; `find --disp` keeps its existing
literal-displacement matching and does not accept this flag.

## Preserve residual labels and gotos

```sh
xref -b app.elf c 0x1000 --goto
xref -b app.elf c 0x1000 --goto --fields --out out-functions
xref -b app.elf slice 0x1000 --to 0x1013 --goto
xref -b app.elf dump --out out-modules --goto
```

The default renderer restructures residual forward jumps with local `skip_*`
flags when possible. `--goto` preserves those residual jumps as `goto L_<addr>;`
and destination labels. Ordinary `if`/`else`, loops and switches remain
structured. This is a display choice for the same recovered function; it does
not improve instruction coverage or prove that the reconstruction is correct.

Use `--fields` independently of `--goto`. The mode also applies to each file
written by `c --out` or `dump`. In a backward slice, retained transfers must
keep their destinations so the displayed control flow remains self-contained.

The commands above illustrate the syntax; addresses depend on the input binary.

## Restrict pseudo-C to paths reaching an address

```sh
xref -b app.elf c 0x1000 --only-paths-to 0x1050
xref -b app.elf c 0x1000 --only-paths-to 0x1050 --goto
```

`xref c FN --only-paths-to ADDR` emits pseudo-C containing only basic blocks that
can reach `ADDR` (an instruction address inside `FN`) plus the statements those
blocks need, with elided regions marked by a one-line comment (`/* ... */`).
Unrelated branches and trailing blocks that cannot reach `ADDR` are omitted. If
`ADDR` is outside `FN` or unreachable from the entry block, the command reports
a clear error. Blocks are kept whole: the statement for `ADDR` carries
`/* @xref_slice_target */`, and statements after it in the same basic block are
still shown. Switch arms and labels that lead only to pruned code stay as
`/* ... */` stubs so every emitted label is defined.
