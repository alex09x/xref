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
$ xref -b rg profile import --out rg-perf.xprof --maps rg.maps --pid 4084848 rg.perf.data
```

```text output
profile imported to rg-perf.xprof
```

```stderr
xref: load 2.7ms, total 28.1ms
```
<!-- /xref -->

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg-perf.xprof --top 6
```

```text output
3991 samples, 0 lost, 0 dropped; partial=true
target mapping: [caller-supplied target mapping]
  42.70% self   67.35% total       1704 [kernel]:unknown
  19.82% self   75.02% total        791 target:unknown
   6.01% self    6.21% total        240 target:fn_fc020
   4.51% self    8.09% total        180 target:fn_4302b0
   4.18% self    4.26% total        167 target:fn_fb4b0
   4.08% self    4.54% total        163 target:fn_de140
warning: import_target_mapping_is_synthetic_and_base_is_unverified
warning: perf_data_may_have_missing_identity_mapping_or_sample_metadata
warning: unresolved_frames_preserved_by_module
```

```stderr
xref: load 2.5ms, total 8.5ms
```
<!-- /xref -->

## Limits

- The mapping is supplied by the caller, so it is marked synthetic and its
  base unverified; a wrong maps file gives wrong attributions.
- Call chains are taken as `perf` recorded them; xref does not unwind them
  again.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
