# xref find

Functions satisfying multiple predicates in one parallel pass.

Intersects string refs, callees, immediate constants, struct displacements, panic source paths, and byte-size bounds in one rayon pass.

## Usage

<!-- xref:usage find -->
```text
xref find [OPTIONS]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options find -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--calls <CALLS>` | Function calls or tail-jumps to ADDR (repeatable). |  |
| `--refs <REFS>` | Function references string or hex address (repeatable). |  |
| `--imm <IMM>` | Function uses immediate constant N (repeatable). |  |
| `--store` | Only `mov [mem], imm` stores for `--imm`. |  |
| `--cmp` | Only `cmp` instructions for `--imm`. |  |
| `--disp <DISP>` | Function accesses struct field at displacement OFF (repeatable). |  |
| `--write` | Only memory writes for `--disp`. |  |
| `--lea` | Only `lea` address-of uses for `--disp`. |  |
| `--src <SRC>` | Function references panic Location matching PATTERN (repeatable). |  |
| `--size <SIZE>` | Function byte size range (`MIN..MAX`, `MIN..`, `..MAX`, or `EXACT`). |  |
| `--any <ANY>` | Minimum number of predicates to satisfy (default: all); ranks by match count. |  |
| `--back <BACK>` | Bytes before each `--refs` string to include in reachability window. | `16` |
| `--insn <INSN>` | Instruction mnemonic with optional Intel operand glob (repeatable). |  |
| `--class <CLASS>` | Instruction class; currently `float` (repeatable). |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Find --refs "goto L_" --imm 7

Functions referencing string "goto L_" and immediate constant 7.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped find --refs "goto L_" --imm 7
```

```text output
0x87430..0x8a33a  size 0x2f0a  (2/2: refs:goto L_@0x886be, imm:0x7@0x8769a)
0x9f520..0xa2196  size 0x2c76  (2/2: refs:goto L_@0xa0e51, imm:0x7@0x9fb93)
0xc7d60..0xc7fbf  size 0x25f  (2/2: refs:goto L_@0xc7e04, imm:0x7@0xc7df5)
0xc7fc0..0xd0a9d  size 0x8add  (2/2: refs:goto L_@0xcc270, imm:0x7@0xc881b)
0xd0aa0..0xd0d73  size 0x2d3  (2/2: refs:goto L_@0xd0acf, imm:0x7@0xd0bbe)
0xd5490..0xd57b1  size 0x321  (2/2: refs:goto L_@0xd54bf, imm:0x7@0xd55ce)
0xd7740..0xf13ff  size 0x19cbf  (2/2: refs:goto L_@0xedc34, imm:0x7@0xdbd81)
7 functions
```

```stderr
xref: load 521.1µs, total 2.6ms
```
<!-- /xref -->

### Find --src src/loops.rs --calls 0x160bb0

Functions attributed to src/loops.rs that call 0x160bb0.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped find --src src/loops.rs --calls 0x160bb0
```

```text output
0xc7d60..0xc7fbf  size 0x25f  (2/2: calls:0x160bb0@0xc7fba, src:src/loops.rs@0xc7faa)
0xc7fc0..0xd0a9d  size 0x8add  (2/2: calls:0x160bb0@0xcf3cc, src:src/loops.rs@0xd02de)
2 functions
```

```stderr
xref: load 501.2µs, total 2.3ms
```
<!-- /xref -->

### Find --disp 0x8 --disp 0x10 --size 600..850

Functions touching both +0x8 and +0x10 whose code size is between 600 and 850 bytes.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped find --disp 0x8 --disp 0x10 --size 600..850
```

```text output
0x5dd40..0x5e016  size 0x2d6  (3/3: disp:0x8@0x5de5d, disp:0x10@0x5ddac, size:600..850@0x5dd40)
0x5e020..0x5e2f6  size 0x2d6  (3/3: disp:0x8@0x5e13d, disp:0x10@0x5e08c, size:600..850@0x5e020)
0x65e30..0x66179  size 0x349  (3/3: disp:0x8@0x65e89, disp:0x10@0x65e59, size:600..850@0x65e30)
0x686b0..0x689ce  size 0x31e  (3/3: disp:0x8@0x686ca, disp:0x10@0x686ce, size:600..850@0x686b0)
0x689d0..0x68cfe  size 0x32e  (3/3: disp:0x8@0x689ea, disp:0x10@0x689ee, size:600..850@0x689d0)
0x68d00..0x69000  size 0x300  (3/3: disp:0x8@0x68d15, disp:0x10@0x68d19, size:600..850@0x68d00)
0x690d0..0x693d0  size 0x300  (3/3: disp:0x8@0x690e5, disp:0x10@0x690e9, size:600..850@0x690d0)
0x693d0..0x696bc  size 0x2ec  (3/3: disp:0x8@0x693e5, disp:0x10@0x693e9, size:600..850@0x693d0)
0x6f910..0x6fbd4  size 0x2c4  (3/3: disp:0x8@0x6f91b, disp:0x10@0x6f935, size:600..850@0x6f910)
0x94e20..0x950f7  size 0x2d7  (3/3: disp:0x8@0x94ed0, disp:0x10@0x94f8e, size:600..850@0x94e20)
0x95480..0x9575b  size 0x2db  (3/3: disp:0x8@0x95499, disp:0x10@0x954a2, size:600..850@0x95480)
0x96020..0x96362  size 0x342  (3/3: disp:0x8@0x960de, disp:0x10@0x9620c, size:600..850@0x96020)
0x96720..0x96a6f  size 0x34f  (3/3: disp:0x8@0x967d9, disp:0x10@0x96961, size:600..850@0x96720)
0x9a980..0x9ac0c  size 0x28c  (3/3: disp:0x8@0x9a98e, disp:0x10@0x9a992, size:600..850@0x9a980)
0x9e4a0..0x9e718  size 0x278  (3/3: disp:0x8@0x9e639, disp:0x10@0x9e63d, size:600..850@0x9e4a0)
0xa2270..0xa2566  size 0x2f6  (3/3: disp:0x8@0xa22d1, disp:0x10@0xa22cb, size:600..850@0xa2270)
0xa84b0..0xa87e5  size 0x335  (3/3: disp:0x8@0xa8560, disp:0x10@0xa8568, size:600..850@0xa84b0)
0xa87f0..0xa8b3b  size 0x34b  (3/3: disp:0x8@0xa888c, disp:0x10@0xa8894, size:600..850@0xa87f0)
0xaa8f0..0xaac41  size 0x351  (3/3: disp:0x8@0xaa91b, disp:0x10@0xaa928, size:600..850@0xaa8f0)
0xaac50..0xaafa1  size 0x351  (3/3: disp:0x8@0xaac7b, disp:0x10@0xaac88, size:600..850@0xaac50)
0xaafb0..0xab2a9  size 0x2f9  (3/3: disp:0x8@0xaafd7, disp:0x10@0xaafe4, size:600..850@0xaafb0)
0xab2b0..0xab601  size 0x351  (3/3: disp:0x8@0xab2db, disp:0x10@0xab2e8, size:600..850@0xab2b0)
0xc3550..0xc385d  size 0x30d  (3/3: disp:0x8@0xc3630, disp:0x10@0xc35e0, size:600..850@0xc3550)
0xc7ac0..0xc7d55  size 0x295  (3/3: disp:0x8@0xc7b35, disp:0x10@0xc7b2f, size:600..850@0xc7ac0)
0xc7d60..0xc7fbf  size 0x25f  (3/3: disp:0x8@0xc7ded, disp:0x10@0xc7df1, size:600..850@0xc7d60)
0xd0aa0..0xd0d73  size 0x2d3  (3/3: disp:0x8@0xd0b62, disp:0x10@0xd0b3f, size:600..850@0xd0aa0)
0xd5120..0xd53fa  size 0x2da  (3/3: disp:0x8@0xd5260, disp:0x10@0xd5200, size:600..850@0xd5120)
0xd5490..0xd57b1  size 0x321  (3/3: disp:0x8@0xd558e, disp:0x10@0xd553e, size:600..850@0xd5490)
0xd6e20..0xd708a  size 0x26a  (3/3: disp:0x8@0xd6e6a, disp:0x10@0xd6e49, size:600..850@0xd6e20)
0xd74b0..0xd7732  size 0x282  (3/3: disp:0x8@0xd7629, disp:0x10@0xd7652, size:600..850@0xd74b0)
0xfad70..0xfafdb  size 0x26b  (3/3: disp:0x8@0xfad87, disp:0x10@0xfae16, size:600..850@0xfad70)
0xfba90..0xfbda2  size 0x312  (3/3: disp:0x8@0xfbd79, disp:0x10@0xfbd7d, size:600..850@0xfba90)
0xfc160..0xfc3f3  size 0x293  (3/3: disp:0x8@0xfc345, disp:0x10@0xfc239, size:600..850@0xfc160)
0xfe590..0xfe844  size 0x2b4  (3/3: disp:0x8@0xfe59f, disp:0x10@0xfe5c3, size:600..850@0xfe590)
0xfe850..0xfead0  size 0x280  (3/3: disp:0x8@0xfe85b, disp:0x10@0xfe88b, size:600..850@0xfe850)
0xfead0..0xfed50  size 0x280  (3/3: disp:0x8@0xfeadb, disp:0x10@0xfeb0b, size:600..850@0xfead0)
0xfed50..0xfefd0  size 0x280  (3/3: disp:0x8@0xfed5b, disp:0x10@0xfed8b, size:600..850@0xfed50)
0xff460..0xff6c5  size 0x265  (3/3: disp:0x8@0xff46b, disp:0x10@0xff48f, size:600..850@0xff460)
0xffb50..0xffdb5  size 0x265  (3/3: disp:0x8@0xffb5b, disp:0x10@0xffb7f, size:600..850@0xffb50)
0xffdc0..0x10010a  size 0x34a  (3/3: disp:0x8@0xffdcf, disp:0x10@0xffe0b, size:600..850@0xffdc0)
```
*Output cut here: lines 1–40 of 89 shown.*

```stderr
xref: load 505.5µs, total 2.2ms
```
<!-- /xref -->

## Reading the output

- One line per function that satisfies the predicates: its range and size, then `(matched/total: …)` with the first witness of each predicate (the instruction or reference that satisfied it).
- The last line counts the functions. `--any K` accepts functions matching at least K predicates.

## Limits

- Predicates are evaluated per function on instruction evidence; a string reached only through a callee does not count for the caller.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
