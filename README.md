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
xref -b BIN refs "some text" 0x439041     # code and data slots naming a text or address
xref -b BIN error "some text"             # enum variant whose Display arm names the text
xref -b BIN variant 0x44b4ff0 61 404     # inverse of error: texts of jump-table arms
xref -b BIN imm 9 --cmp --in 0x23103b4    # constants (--store: mov [mem],imm; --cmp)
xref -b BIN callers 0x2d909f8             # direct calls/jumps, address taken, pointer slots
xref -b BIN calls 0x2c2a38d               # calls and tail jumps of a function in code order
xref -b BIN asm 0x44b4ff0 --from A --to B # annotated disassembly (strings, slots, targets)
xref -b BIN src 0x2c2a38d                 # Rust source file:line the function panics with
xref -b BIN where src/order.rs            # functions compiled from a source file
xref -b BIN files src/                    # source files known from panic locations
```

`XREF_BIN` replaces `-b`. Addresses are ELF virtual addresses (objdump numbering): `0x` hex or
decimal.

## Tests

`cargo test` runs the unit tests and the end-to-end tests, which build
`tests/fixtures/sample.rs` with the toolchain's `rustc` and query the result.
