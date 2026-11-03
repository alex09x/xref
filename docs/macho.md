# Mach-O input support

This feature is in source revisions after v0.1.0. Published v0.1.0 binaries
and the registry package remain ELF-only. Build the corresponding source.

Supported inputs: thin little-endian x86-64 Mach-O executables, dylibs and
bundles with usable DWARF `__eh_frame`. An arm64 macOS host can analyze these
x86-64 inputs. ARM64 input, 32-bit, fat/universal, encrypted, relocatable,
kernel/cache/fileset and compact-unwind-only images are rejected. Input
binaries are read and never executed.

## Addresses and function evidence

The JSON/MCP identity uses `format: "macho"`, architecture `x86_64`,
and `rva_basis: "macho_text_segment_vmaddr"`. Base is `__TEXT.vmaddr`;
zero-file-size `__PAGEZERO` cannot become RVA base zero. LC_MAIN offsets and
supported LC_UNIXTHREAD x86-64 states are normalized to VAs. No ASLR slide
is inferred.

Typed function ranges still have `range_origin: "eh_frame_fde"`: an unwind
range is not proof of a whole source function. LC_FUNCTION_STARTS is compared
with FDE starts; incomplete coverage is visible in warnings and
`info.format_details`. Compact-only functions in mixed images return
`no_function` through the strict typed API. Human CLI synthetic spans remain
labelled synthetic and are bounded by the instruction section and next
recorded function start.

File-backed linkage mappings remain readable by VA, but literal byte searches
exclude `__LINKEDIT`, avoiding symbol-table spelling as a program-string hit.
Function symbols keep raw linker spelling. Import names lose exactly one
leading Mach-O underscore for the existing signature recognizer.

## Linkage and reconstruction

Supported: indirect pointer/stub symbol slots; legacy dyld pointer
rebase/bind/lazy/weak streams; x86-64 chained PTR_64 and PTR_64_OFFSET; chained
import formats 1–3 with uncompressed names; export tries and defined external
symbols. Unsupported threaded, authenticated, compressed and other pointer
forms report incomplete metadata. Encoded chain words never become guessed
target addresses; nonzero bind addends remain unresolved.

Legacy cursor movement follows dyld wrapping semantics, with strict bounds
checked at every slot. File extents and VAs use checked arithmetic. Export
traversal uses an explicit stack. Limits: one million decoded operations and
64 MiB total decoded name bytes. Malformed extents, duplicate singleton
commands, invalid indices and cyclic export graphs fail explicitly.

Recorded Mach-O callers do not prove a closed return contract. Returns cannot
be deleted or narrowed merely because those callers ignore them. Potential
RAX/RDX output is preserved through the existing heuristic reconstruction.
C, layouts, slices and types remain heuristic; inspect warnings and raw ASM.

The same loader serves CLI, JSON queries and local MCP. Use a returned FDE VA
and an exact call-site instruction to inspect/slice it. See [MCP](mcp.md) and
[bounded investigations](investigations.md).

## Fixture provenance

`tests/fixtures/macho/` contains redistributable inputs from the included
assembly and a simple C leaf. `generate.py` runs Xcode's `xcrun clang` on
macOS and never executes outputs. JSON manifests record hashes, symbols,
mapping geometry and known instruction targets. Legacy, chained, mixed-CFI,
dylib and bundle profiles exercise the adapter. Linux tests use the checked-in
inputs without needing a Mach-O linker.

Tests check identity, VAs, FDEs, references/calls, pointers, imports, exported
and address-taken returns, a register-pair return, coverage gaps, malformed
input, and CLI/MCP slice parity. Fixture regeneration is separate from normal
test execution.
