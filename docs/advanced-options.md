# Stack displacement searches and label-preserving output

Introduced after v0.1.0. The v0.1.0 binaries do not include these flags.

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

The query still matches the literal displacement encoded in the instruction.
For example, a read from `[rsp + 0x30 + 0x20]` encodes displacement `0x50`:
search for `0x50`, not `0x20`. This option does not infer where an aggregate
starts or which stack slots belong to one source-level structure.

Negative frame displacements use the same 64-bit representation as other
displacement queries. For `[rbp - 0x20]`, use:

```sh
xref -b app.elf disp 0xffffffffffffffe0 --stack
```

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
