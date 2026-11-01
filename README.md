# xref

Ultra blazing fast cross-references of an x86-64 ELF binary: which code names a string, an enum
variant, a constant or a function, and which Rust source file a function was compiled from.

Every query decodes every function on every core. Function ranges come from `.eh_frame`, so they
are exact even in stripped binaries where disassemblers find no function. No index is kept, so
nothing goes stale.

```
xref -b BIN stats                         # functions, pointers, imports, panic locations
xref -b BIN sym NAME                      # function symbols (non-stripped binaries)
xref -b BIN func 0xa1b50                  # exact function range containing an address
xref -b BIN refs "goto L_" 0xa1b50        # code and data slots naming a text or address (--inline: movabs)
xref -b BIN error "invalid"               # enum variant whose Display arm names the text
xref -b BIN variant 0x9e840 1 2           # inverse of error: texts of jump-table arms
xref -b BIN imm 24 --in 0xa1b50           # constants (--store: mov [mem],imm; --cmp)
xref -b BIN disp 0x20 0x28 --all          # struct field accesses (--write, --lea, --all, --stride 0x18, --in FN)
xref -b BIN layout 0x9e840 --reg rsi --callees # reconstruct struct field offsets, types, strides and callees
xref -b BIN callers 0xcafb0               # direct calls/jumps, address taken, pointer slots
xref -b BIN calls 0xcafb0                 # calls and tail jumps of a function in code order
xref -b BIN args 0xcafb0                  # constant/symbolic arguments at every call site (--max N)
xref -b BIN find --src src/loops.rs --calls 0x15a8f0 # functions matching multiple predicates in one pass
xref -b BIN path 0xb3180 0x15a8f0         # shortest call chains between two functions (--depth N)
xref -b BIN tree 0xb3180 --callees        # caller or callee tree with ranges and panic locations
xref -b BIN match --other OLD_BIN 0x9e840 # match functions across two builds of a binary
xref -b BIN diff-c --other OLD_BIN 0x9e840 # cross-build normalized pseudo-C logic diff
xref -b BIN asm 0xcafb0 --from A --to B   # annotated disassembly (strings, slots, targets)
xref -b BIN c 0x9e840 --fields            # structured pseudo-C with struct/Vec field sugar
xref -b BIN slice 0xcafb0 --to fn_15a8f0  # backward program slice to target call/field/ip
xref -b BIN dump --out DIR --src src/     # parallel modular source-tree pseudo-C dump
xref -b BIN src 0x9e840                   # Rust source file:line the function panics with
xref -b BIN where src/loops.rs            # functions compiled from a source file
xref -b BIN files src/                    # source files known from panic locations
```

`XREF_BIN` replaces `-b`. Addresses are ELF virtual addresses (objdump numbering): `0x` hex or
decimal.

## Tests

`cargo test` runs the unit tests and the end-to-end tests, which build
`tests/fixtures/sample.rs` with the toolchain's `rustc` and query the result.
