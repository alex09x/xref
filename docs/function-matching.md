# Instruction search and cross-build ambiguity

These workflow additions are available starting with v0.4.0.

```sh
xref -b app find --insn sqrtsd
xref -b app find --insn 'divsd xmm*' --size 0x10..0x400
xref -b app find --class float --insn cvtsi2sd --any 1
```

`--insn` accepts an exact case-insensitive mnemonic and an optional glob over
Intel-format operands. `*` and `?` are glob operators; there is no regular
expression or shell evaluation. Whitespace in operands is ignored. Up to 32
instruction/class filters of at most 32 bytes each can be combined with the
existing predicates. `--any` counts satisfied predicates, not instructions.

`float` selects an explicit set of floating-point arithmetic and conversion
forms, including scalar/vector SSE, AVX, FMA and x87 forms. Integer SIMD does
not match merely because it uses XMM/YMM registers. It is a supported mnemonic
set, not a claim that every future floating-point opcode is recognized.
Results include function ranges, match counts and at most eight instruction
addresses per predicate, with omitted counts. Overlapping predicates can count
the same instruction separately. Without new filters, legacy output is kept.

```sh
xref -b old-app match --other new-app 0x12340 --top 5
xref -b old-app match --other new-app 0x12340 --ambiguity-ratio 0.98 --diff --json
xref -b old-app match --other new-app 0x12340 --context 0x11000 0x22000
```

The runner-up/best structural score ratio is a heuristic, not a probability.
The default ambiguity threshold is 0.95. Exact ties remain ambiguous. Output
shows structural margin and bounded distinguishing evidence for immediates,
string fingerprints, displacements and callees. Callee addresses belong to
their own images; equal numeric addresses do not establish correspondence.
Fingerprints and layout similarities are also evidence rather than identity
proof.

`--diff` compares at most eight plausible candidates using normalized pseudo-C.
Function code is capped at 64 KiB before decompilation and normalized output
at 128 lines; unsupported, empty, limited or failed comparisons remain explicit.
All plausible candidates must have complete comparisons before pseudo-C can
resolve structural ambiguity. Close similarity scores and exact normalized
ties remain ambiguous. Pseudo-C ordering is inference, not proof that the
functions are semantically equivalent.

`--context` takes an already matched **pair** of callers, first in the query
image and then in the other image. Positive static reachability boosts a
candidate. An unresolved indirect call does not establish non-reachability.
At most 64 query functions and 128 returned candidates per function are
supported; omitted plausible candidates preserve ambiguity.

Automatic `diff-c` refuses an ambiguous counterpart and asks for `--target`.
An explicit target is the operator's selection and is labeled accordingly.
The JSON matching output includes both image hashes and uses hexadecimal
range addresses so the two builds' coordinate spaces remain clear.

The matcher and instruction tests compile redistributable C/assembly fixtures
and derive instruction/function oracles from their symbols before creating
stripped ELF copies. Identical twins, different logic, shifted addresses,
positive caller anchors, unknown comparisons and integer SIMD are separate
controls. No private consumer binary or prebuilt fixture is required.
