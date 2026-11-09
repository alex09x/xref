# xref edges

Import observed caller → callee adjacencies from saved stacks (address lists,
`perf script` call chains, folded stacks) into an evidence store that graph
queries use when asked to. Static call graphs miss calls through pointers;
observed stacks fill some of them in. Counts are stack samples, not call
counts.

## Usage

<!-- xref:usage edges import -->
```text
xref edges import [OPTIONS] --out <OUT>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options edges import -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--input <INPUT>` | Saved addresses, perf script, or root-first folded stacks; '-' reads stdin. | `-` |
| `--format <FORMAT>` | [possible values: addresses, perf, folded]. | `addresses` |
| `--base <BASE>` | Runtime address of the lowest image virtual address (not an arbitrary text mapping). |  |
| `--maps <MAPS>` | Saved /proc/PID/maps from the sampled process, not the current process. |  |
| `--target-path <TARGET_PATH>` | Original executable path as it appears in maps/MMAP records. |  |
| `--pid <PID>` | Process TGID to select from perf-script samples. |  |
| `--build-id <BUILD_ID>` | Reject a mismatch against the selected binary's build ID. |  |
| `--kind <KIND>` | Auto: sampled leaf is instruction IP, ancestors are return addresses [possible values: auto, instruction, return-address, static, symbol]. | `auto` |
| `--max-bytes <MAX_BYTES>` | Input byte budget; reading stops there and the result is marked truncated. | `2147483648` |
| `--max-samples <MAX_SAMPLES>` | Stack sample budget; reading stops there and the result is marked truncated. | `100000` |
| `--timeout-ms <TIMEOUT_MS>` | Time budget in milliseconds; reading stops there and the result is marked truncated. | `30000` |
| `--out <OUT>` | Path of the edge evidence store to write. |  |
<!-- /xref -->

## Examples

### Edges from a perf recording

The ripgrep recording from [`profile import`](profile-import.md), converted
with `perf script -i rg.perf.data > rg.perf.txt`:

<!-- xref:run max=20 -->
```console
$ xref -b rg edges import --format perf --input rg.perf.txt --maps rg.maps --pid 4084848 --out rg.edges
```

```text output
imported 0 observed stack-adjacency edges from 0 samples; counts are stack samples
warning: fde_ranges_are_not_source_function_boundaries
warning: imported_trace_producer_not_authenticated
warning: perf_callchain_ancestors_treated_as_return_addresses
warning: stack_adjacency_and_sample_counts_are_not_direct_calls_or_invocation_counts
```

```stderr
xref: load 2.5ms, total 34.9ms
```
<!-- /xref -->

Formats, the store, and how queries opt in: [Offline stacks and observed call
evidence](../trace-analysis.md).

## Limits

- Adjacent frames show that one function was on the stack under another, not
  how many calls were made.
- The mapping is supplied by the caller (`--maps` or `--base`); a wrong one
  gives wrong edges.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
