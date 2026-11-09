# xref match

Counterpart of each function in another build of the binary, scored by shared locations, strings, immediates and call graph.

Matches stripped functions between two builds (68aa57b vs v0.0.2 / e6037d0) by structural invariants and diffs normalized pseudo-C without address noise.

## Usage

<!-- xref:usage match -->
```text
xref match [OPTIONS] --other <OTHER> <ADDRS>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options match -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDRS>...` | Functions in this binary to match (addresses or symbol names). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--other <OTHER>` | The other build of the binary to search for counterparts. |  |
| `--top <TOP>` | Number of candidates shown, 1..=128. | `5` |
| `--ambiguity-ratio <AMBIGUITY_RATIO>` | Runner-up / best structural score ratio triggering ambiguity (not a probability). | `0.95` |
| `--diff` | Compare bounded plausible candidates by normalized pseudo-C similarity. |  |
| `--context <QUERY_CALLER> <OTHER_CALLER>` | Already matched caller pair: query-side caller followed by other-side caller. |  |
| `--json` | Emit the matches as JSON. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Match --other xref-v0.0.2.stripped ...

Relocates 4 stripped functions from 68aa57b against stripped v0.0.2 despite shifted virtual addresses.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped match --other xref-v0.0.2.stripped 0xc7d60 0x9ef60 0xa2270 0xd57c0 --top 2
```

```text output
query 0xc7d60..0xc7fbf
  structural score margin 101 runner-up ratio 0.613 (heuristic; not a probability)
  0xcf8d0..0xcfb2f  score 261  (locs:80 strs:0 imms:11 disps:0 nbrs:145 size:0x25f callees:4)
    string_fingerprints: query-only ["0x281a8e879de07d73"], candidate-only ["0x789340d0b05c9f28"]; FNV-1a fingerprints, not string identity proof
    callee_addresses: query-only ["0xa5e20", "0x124d50", "0x160550", "0x160bb0"], candidate-only ["0xa8200", "0x113ae0", "0x14fe20", "0x150440"]; addresses are scoped to their own image; not compared across builds
  0x1126e0..0x112cd5  score 160  (locs:0 strs:0 imms:0 disps:0 nbrs:145 size:0x5f5 callees:4)
    immediates: query-only ["0xa8", "0xc0", "0xffffffffffffffdf"], candidate-only ["0x44", "0x118", "0x101010101010100", "0x8080808080808080", "0xfffffffffffffff0"]; literal values, heuristic correspondence
    string_fingerprints: query-only ["0x281a8e879de07d73"], candidate-only []; FNV-1a fingerprints, not string identity proof
    field_displacements: query-only [], candidate-only ["0x20", "0x30", "0x3f", "0x7f"]; literal displacements, not common type proof
    callee_addresses: query-only ["0xa5e20", "0x124d50", "0x160550", "0x160bb0"], candidate-only ["0x9db20", "0x113ae0", "0x14f021", "0x14fe20"]; addresses are scoped to their own image; not compared across builds
    callee_immediates: query-only [], candidate-only ["0xfffffffffffffffd"]; 64-bit immediate evidence from static callees
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 292; omitted plausible candidates keep ambiguity
query 0x9ef60..0x9f518
  structural score margin 86 runner-up ratio 0.771 (heuristic; not a probability)
  0xa0ca0..0xa1258  score 376  (locs:80 strs:0 imms:11 disps:0 nbrs:260 size:0x5b8 callees:4)
    callee_addresses: query-only ["0x6d5e0", "0x86340", "0x131ec0", "0x15fe80"], candidate-only ["0x73ba0", "0x89590", "0x121010", "0x14ef40"]; addresses are scoped to their own image; not compared across builds
  0x6c5e0..0x6cc15  score 290  (locs:0 strs:0 imms:7 disps:0 nbrs:260 size:0x635 callees:4)
    immediates: query-only ["0x44", "0xa8", "0xfffffffffffffff0"], candidate-only ["0x68", "0xffffffffffffffe8"]; literal values, heuristic correspondence
    callee_addresses: query-only ["0x6d5e0", "0x86340", "0x131ec0", "0x15fe80"], candidate-only ["0x73ba0", "0x89590", "0xedcf0", "0x1158ed"]; addresses are scoped to their own image; not compared across builds
    callee_immediates: query-only [], candidate-only ["0x7ffffffffffffff9"]; 64-bit immediate evidence from static callees
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 343; omitted plausible candidates keep ambiguity
query 0xa2270..0xa2566
  structural score margin 149 runner-up ratio 0.685 (heuristic; not a probability)
  0xa3fb0..0xa42a6  score 473  (locs:80 strs:0 imms:93 disps:0 nbrs:275 size:0x2f6 callees:5)
    callee_addresses: query-only ["0x126470", "0x1267c5", "0x1267f0", "0x126900", "0x15fe80"], candidate-only ["0x1158ed", "0x115920", "0x115a30", "0x14ef40", "0x1559a0"]; addresses are scoped to their own image; not compared across builds
  0x1c47e0..0x1c4ac9  score 324  (locs:0 strs:0 imms:0 disps:0 nbrs:300 size:0x2e9 callees:5)
    immediates: query-only ["0x5e", "0x5f", "0xe0", "0xffffffffffffffbf", "0xffffffffffffffe8", "0xfffffffffffffff7"], candidate-only ["0x13e"]; literal values, heuristic correspondence
    string_fingerprints: query-only [], candidate-only ["0x414251d714a92a74", "0xc298de2f9ced2ba8", "0xd3ff4d30127d26e3"]; FNV-1a fingerprints, not string identity proof
    field_displacements: query-only ["0x20", "0x28", "0x40"], candidate-only []; literal displacements, not common type proof
    callee_addresses: query-only ["0x126470", "0x1267c5", "0x1267f0", "0x126900", "0x15fe80"], candidate-only ["0x14d240", "0x14ef40", "0x150970", "0x150a33", "0x1c4d73"]; addresses are scoped to their own image; not compared across builds
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 397; omitted plausible candidates keep ambiguity
query 0xd57c0..0xd6301
  structural score margin 173 runner-up ratio 0.549 (heuristic; not a probability)
  0xd5530..0xd6071  score 384  (locs:240 strs:0 imms:4 disps:10 nbrs:105 size:0xb41 callees:8)
    callee_addresses: query-only ["0x69710", "0x69770", "0x95760", "0xa5e90", "0xc7d60", "0x1267c5", "0x15ff61", "0x161030"], candidate-only ["0x6ff90", "0x6fff0", "0x99520", "0xa8270", "0xcf8d0", "0x1158ed", "0x14f021", "0x1508c0"]; addresses are scoped to their own image; not compared across builds
  0xb4860..0xba77c  score 211  (locs:128 strs:0 imms:2 disps:10 nbrs:70 size:0x5f1c callees:30)
    immediates: query-only ["0x88"], candidate-only ["0x58", "0x60", "0x7b", "0x7d", "0x85", "0xb8", "0xbf", "0xdf"]; literal values, heuristic correspondence; truncated
```
*Output cut here: lines 1–40 of 46 shown.*

```stderr
xref: load 822.5µs, total 13.5ms
```
<!-- /xref -->

## Reading the output

- For each queried function: the best counterparts in the other build with their score and its parts (`locs` shared source locations, `strs` strings, `imms` immediates, `disps` displacements, `nbrs` call-graph neighbours, `size`, `callees`).
- `structural score margin` and `runner-up ratio` say how far the best candidate is ahead; the indented lines list evidence present on only one side.
- `warning:` lines state that scores are heuristics and when the candidate list was capped.

## Limits

- Scores are heuristics, not probabilities; a small margin means several plausible counterparts. Confirm with [`diff-c`](diff-c.md).

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
