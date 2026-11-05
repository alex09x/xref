# xref symbolize

Map addresses from a saved run onto the selected executable: plain address
lists, `perf script` call chains or folded stacks. It never attaches to a
process. Frames outside the executable, in shared libraries, in an ambiguous
mapping or in a range without unwind information stay explicitly unresolved.

## Usage

<!-- xref:usage symbolize -->
```text
xref symbolize [OPTIONS]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options symbolize -->
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
| `--jsonl` | Stream one JSON object per sample, followed by a summary object. |  |
| `--folded` | Aggregate canonical root-first function stacks (bounded memory) [alias: --collapse]. |  |
| `--group-callers` | Include exact decoded return call-sites in ancestor grouping keys. |  |
| `--group-by <GROUP_BY>` | Count samples by the immediate caller's call site; unknown caller stays unknown [possible values: caller]. |  |
<!-- /xref -->

## Examples

```sh
# One leaf-first address stack per line; BASE is the runtime image base.
xref -b app symbolize --input addresses.txt --base 0x555555554000
# Use the saved /proc/<pid>/maps instead of a base.
xref -b app symbolize --input addresses.txt --maps saved.maps --target-path /opt/app
# perf script call chains, grouped by caller.
xref -b app symbolize --format perf --input stacks.perf.txt --pid 1234 --group-by caller
```

Formats, mapping rules and output: [Offline stacks and observed call
evidence](../trace-analysis.md).

## Provenance

These examples show syntax only; they are not recorded.
