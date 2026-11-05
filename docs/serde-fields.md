# Serialized field names and input-relative access candidates

This workflow, available starting with v0.4.0, connects a literal key and
length to an input-relative value in a known function-call model:

```sh
xref -b app field validator_to_staged_rewards --json --layout-only
xref -b app field validator_to_staged_rewards --within 0x12340 --json
xref -b app field validator_to_staged_rewards --within 0x12340 \
  --write --min-offsets 2 --limit 64
```

`--within` selects the function whose **input argument** is the layout root.
Different functions may receive a containing object, a nested inline object,
or a field reference. Their relative offsets have different origins; inspect
`function`, `base_argument`, the literal key and the static evidence steps.
The JSON includes the selected binary's SHA-256.

Candidates show named offsets, related keys, key/value argument witnesses,
known static helper rebases, instruction read widths and an addressed-span
lower bound. The displayed field order is lexical instruction/call-site
order. It does not claim recovered Rust declaration order or every runtime
path's order. Exact size, alignment, padding and allocation identity remain
unknown. A skipped field or erased/zero-sized value may leave no recoverable
offset in optimized code. No offset is inferred from declaration index times
an assumed word size.

An optimized JSON form may write the key, a colon, and the value through
separate calls. The continuation candidate requires a common symbolic state
or a documented reference-cell relationship, CFG dominance, a colon-store
witness, and no intervening key on a known path. A reference-cell relationship
does **not** prove that the writer was not retargeted. Such rows explicitly
set `association_uncertain`, carry an `unverified_*` state-identity marker,
and make the report ambiguous. Their evidence is a static pattern rather
than a runtime writer/type identity proof. Plain string co-occurrence is
insufficient.

The model follows x86-64 SysV integer-register arguments, constant pointer
arithmetic, supported scalar loads, stack spills and known direct or resolved
RIP-slot helpers. CFG joins retain only equal facts; unsupported CFGs and
bounded helper paths remain explicit. Unknown indirect calls, opaque memory
changes, aggregate/scalar promotion and other unsupported forms may be missed.
Register positions are argument candidates rather than recovered source
signatures. Literal-key/value evidence does not prove the code implements
Serde, or that two candidates have the same concrete Rust type.

The accessor phase checks each function's accesses relative to the **same
input root**, using the candidate's offset constellation. `--min-offsets 2`
requires at least two distinct matching offsets; `--min-offsets 1` allows weak
single-offset matches and labels them accordingly. `--write` includes accesses
that may write the queried offset, including conditional writes. This is a
way to reduce unrelated matches, not a type-identity test. `--layout-only`
skips that global phase while inspecting or selecting a candidate layout.
Access widths are respected: a wide load/store can cover a field whose start
is inside its byte range. One wide instruction covering multiple offsets is
explicitly labeled `single_span_overlap_not_type_proof`; the reported operand
displacement and width remain separate from the field offsets.

Code, function, instruction, stack-fact, summary-depth, time and output-row
budgets are finite. Coverage/truncation information is part of the report.
Missing results mean no candidate under that model and scope, not proof that
a field or accessor does not exist.

The integration fixture uses ordinary Serde derives and serde_json in
unoptimized and optimized native builds, runtime `offset_of!`/`size_of!`
oracles, exported entry/mutator symbols, and stripped copies retaining FDEs.
Duplicate names in distinct types, Rust field reordering, mixed widths,
rename/skip/nesting, a real mutator and a single-offset unrelated writer are
separate controls. The fixture adds no custom key-emission helper to force a
particular analyzer pattern.
