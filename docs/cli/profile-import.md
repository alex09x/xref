# xref profile import

Convert a profile recorded by Linux `perf` (`perf.data` or `perf script`
text) into an `.xprof` recording that the [`profile`](profile-report.md)
commands read. The target's runtime mapping comes from a saved
`/proc/<pid>/maps` (`--maps` with `--pid`) or a base address (`--base`).

## Usage

<!-- xref:usage profile import -->
```text
xref profile import [OPTIONS] --out <OUT> <INPUT>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options profile import -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<INPUT>` | `perf.data` file or `perf script` text. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--out <OUT>` | Path of the new `.xprof` recording. |  |
| `--base <BASE>` | Runtime address of the lowest image virtual address, when no maps are given. |  |
| `--maps <MAPS>` | Saved `/proc/PID/maps` of the recorded process. |  |
| `--target-path <TARGET_PATH>` | Executable path as it appears in the maps or perf MMAP records. |  |
| `--pid <PID>` | Process ID to select from the recording. |  |
<!-- /xref -->

## Examples

The ripgrep process from [`live profile`](live-profile.md), recorded with
`perf record -g -p PID -o rg.perf.data -- sleep 1`, with its map saved by
`cat /proc/PID/maps > rg.maps`:

<!-- xref:run -->
```console
$ xref -b rg profile import --out rg-perf.xprof --maps rg.maps --pid 4060909 rg.perf.data
```

```text output
profile imported to rg-perf.xprof
```

```stderr
xref: load 2.4ms, total 27.1ms
```
<!-- /xref -->

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg-perf.xprof --top 6
```

```text output
3960 samples, 0 lost, 0 dropped; partial=true
target mapping: [caller-supplied target mapping]
  43.36% self   68.46% total       1717 [kernel]:unknown
  20.61% self   76.31% total        816 target:unknown
   5.00% self    5.13% total        198 target:fn_fc020
   4.34% self    7.70% total        172 target:fn_4302b0
   4.04% self    4.47% total        160 target:fn_de140
   3.86% self    3.91% total        153 target:fn_fb4b0
warning: import_target_mapping_is_synthetic_and_base_is_unverified
warning: perf_data_may_have_missing_identity_mapping_or_sample_metadata
warning: unresolved_frames_preserved_by_module
```

```stderr
xref: load 2.4ms, total 8.5ms
```
<!-- /xref -->

## Limits

- The mapping is supplied by the caller, so it is marked synthetic and its
  base unverified; a wrong maps file gives wrong attributions.
- Call chains are taken as `perf` recorded them; xref does not unwind them
  again.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
