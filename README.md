# xref

Ultra blazing fast cross-references of an x86-64 ELF binary: which code names a string, an enum
variant, a constant or a function, and which Rust source file a function was compiled from.

Every query decodes every function on every core. Function ranges come from `.eh_frame`, so they
are exact even in stripped binaries where disassemblers find no function. No index is kept, so
nothing goes stale.

```
xref -b BIN stats                         # functions, pointers, imports, panic locations
xref -b BIN sym NAME                      # function symbols (non-stripped binaries)
xref -b BIN func 0x2c2a38d                # exact function range containing an address
xref -b BIN refs "some text" 0x439041     # code and data slots naming a text or address (--inline: movabs)
xref -b BIN error "some text"             # enum variant whose Display arm names the text
xref -b BIN variant 0x44b4ff0 61 404      # inverse of error: texts of jump-table arms
xref -b BIN imm 9 --cmp --in 0x23103b4    # constants (--store: mov [mem],imm; --cmp)
xref -b BIN disp 0x408 0x410 --all        # struct field accesses (--write, --lea, --all, --stride 0x510, --in FN)
xref -b BIN layout 0x2c71dd0 --callees    # reconstruct struct field offsets, types, strides and sub-struct callees
xref -b BIN callers 0x2d909f8             # direct calls/jumps, address taken, pointer slots
xref -b BIN calls 0x2c2a38d               # calls and tail jumps of a function in code order
xref -b BIN args 0x2d37130                # constant/symbolic arguments at every call site (--max N)
xref -b BIN find --calls F --imm 5        # functions matching multiple predicates in one pass
xref -b BIN path 0x2c5e3c0 0x2d37130      # shortest call chains between two functions (--depth N)
xref -b BIN tree 0x2c5e3c0 --callees      # caller or callee tree with ranges and panic locations
xref -b BIN match --other OLD_BIN 0x2d37130 # match functions across two builds of a binary
xref -b BIN asm 0x44b4ff0 --from A --to B # annotated disassembly (strings, slots, targets)
xref -b BIN c 0x44b4ff0 --out DIR         # structured pseudo-C decompilation (alias: decomp)
xref -b BIN web --addr 127.0.0.1:7700     # interactive in-memory web workbench & JSON API
xref -b BIN src 0x2c2a38d                 # Rust source file:line the function panics with
xref -b BIN where src/order.rs            # functions compiled from a source file
xref -b BIN files src/                    # source files known from panic locations
```

`XREF_BIN` replaces `-b`. Addresses are ELF virtual addresses (objdump numbering): `0x` hex or
decimal.

## Tests

`cargo test` runs the unit tests and the end-to-end tests, which build
`tests/fixtures/sample.rs` with the toolchain's `rustc` and query the result.
