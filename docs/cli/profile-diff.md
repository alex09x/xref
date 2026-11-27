# xref profile diff

Compare two profiles by sample share: which functions got hotter or cooler.
Two recordings of the same binary are compared function by function; with
`--other NEW_BINARY` the second profile is of another build, and functions are
paired with [`match`](match.md) (heuristic, and marked as such).

## Usage

<!-- xref:usage profile diff -->
```text
xref profile diff [OPTIONS] <BEFORE> <AFTER>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options profile diff -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<BEFORE>` | The earlier `.xprof` recording. |  |
| `<AFTER>` | The later `.xprof` recording. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--other <OTHER>` | Binary AFTER was recorded from, when it is another build; functions are then paired heuristically. |  |
| `--top <TOP>` | Number of rows to print. | `30` |
| `--json` | Print the comparison as JSON. |  |
| `--by <BY>` | What a row aggregates [possible values: function]. | `function` |
| `--min-delta <MIN_DELTA>` | Omit rows whose share changed by fewer percentage points than this. | `0` |
<!-- /xref -->

## Examples

### Two recordings of the same process

Two one-second [`live profile`](live-profile.md) recordings of the same
ripgrep process:

<!-- xref:run max=12 -->
```console
$ xref -b rg profile diff rg.xprof rg-2.xprof --top 6
```

```text output
sample-share delta; cross-build pairs are heuristic; shared modules omitted
  -9.97%  0xde140 -> 0xde140 [same_image]
  -4.57%  0x138ef0 -> 0x138ef0 [same_image]
  -3.85%  0xfb4b0 -> 0xfb4b0 [same_image]
  -3.46%  0x4307b0 -> 0x4307b0 [same_image]
  +2.79%  0x430060 -> 0x430060 [same_image]
  -2.23%  0x408bf0 -> 0x408bf0 [same_image]
```

```stderr
xref: load 3.6ms, total 95.5ms
```
<!-- /xref -->

## Reading the output

- Each row: the change in sample share, the share before and after, the
  function (its name as [`profile report`](profile-report.md) prints it; both
  names when the two sides differ, `-` when one side has no counterpart), and
  how they were paired: `same_image`, `heuristic` (cross-build match),
  `same_module` or `by_name` (a library or kernel function of the same name in
  both), or `unmatched`.
- Library and kernel functions are included, so a change such as `memset`
  going from 65% to 0% after a buffer stops being zeroed shows up. Heap
  snapshots compare only the binary's functions, because the allocator in libc
  holds every byte.
- `-b` is the build of the BEFORE profile and `--other` the build of AFTER.
  When a recording does not match its build, the error names the profile and
  both image hashes, and says when the two builds are swapped.
- Shares are normalized by each profile's sample count, so recordings of
  different lengths compare directly. Small deltas between two runs of the
  same workload, as here, are sampling noise.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.6.0 (the remapped release build of commit 1171b426, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
