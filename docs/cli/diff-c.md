# xref diff-c

Normalized cross-build pseudo-C diff between counterpart functions in two binaries.

Matches stripped functions between two builds (68aa57b vs v0.0.2 / e6037d0) by structural invariants and diffs normalized pseudo-C without address noise.

## Usage

<!-- xref:usage diff-c -->
```text
xref diff-c [OPTIONS] --other <OTHER> <ADDRS>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options diff-c -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDRS>...` | Functions in this binary to compare (addresses or symbol names). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--other <OTHER>` | The other binary build to compare against. |  |
| `--target <TARGET>` | Explicit counterpart address/symbol in `--other` (auto-matched when omitted). |  |
| `--fields` | Rewrite raw pointer offsets as inferred `->f_<off>` field hints before diffing. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Diff-c ... 0xc7d60 (identical)

Confirms zero logic change in 0xc7d60 vs 0xcf8d0 across builds (116 normalized lines identical).

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xc7d60
```

```text output
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 292; omitted plausible candidates keep ambiguity
  warning: pseudo-C ordering is heuristic inference; structural scores remain explicit
=== diff 0xc7d60..0xc7fbf (current) vs 0xcf8d0..0xcfb2f (other, score 261: locs:80 strs:0 imms:11 disps:0 nbrs:145 size:0x25f callees:4; pseudo-C similarity 1.000 (heuristic)) ===
  identical normalized pseudo-C (116 lines)
```

```stderr
xref: load 518.7µs, total 18.6ms
```
<!-- /xref -->

### Diff-c ... 0xd57c0 (changed)

Compact cross-build diff between 0xd57c0 (68aa57b) and 0xd5530 (v0.0.2).

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped diff-c --other xref-v0.0.2.stripped 0xd57c0
```

```text output
  warning: scores, ratios and pseudo-C similarities are heuristics, not calibrated probabilities or semantic equivalence proof
  warning: candidate list capped at 128 of 396; omitted plausible candidates keep ambiguity
  warning: pseudo-C ordering is heuristic inference; structural scores remain explicit
=== diff 0xd57c0..0xd6301 (current) vs 0xd5530..0xd6071 (other, score 384: locs:240 strs:0 imms:4 disps:10 nbrs:105 size:0xb41 callees:8) ===
  ...
      }
      @var_11 = (@slot_10 + @var_8);
-     @var_1 = 0xc2bc;
+     @var_1 = 0xc518;
      @var_32 = @slot_9;
      switch (*(u64 *)(@var_11)) {
  ...
```

```stderr
xref: load 553.1µs, total 44.9ms
```
<!-- /xref -->

## Reading the output

- The `warning:` lines state that scores and similarities are heuristics.
- The `=== diff` header names both functions, the structural score from [`match`](match.md) and the pseudo-C similarity.
- Then either `identical normalized pseudo-C (N lines)` or a line diff: `-` lines only in the current build, `+` lines only in the other, `...` marks unchanged lines left out. Addresses, labels and skip flags are normalized away before comparing.

## Limits

- Equal normalized pseudo-C is strong evidence of unchanged logic, not a proof; constants folded differently by the compiler show up as differences.
- The counterpart is chosen by `match`; check its score margin when several candidates are close.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
