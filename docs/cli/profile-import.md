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
$ xref -b rg profile import --out rg-perf.xprof --maps rg.maps --pid 244321 rg.perf.data
```

*(no stdout)*

Exit status 1.

```stderr
xref: no samples for the selected PID in perf.data
```
<!-- /xref -->

<!-- xref:run max=12 -->
```console
$ xref -b rg profile report rg-perf.xprof --top 6
```

*(no stdout)*

Exit status 1.

```stderr
xref: No such file or directory (os error 2)
```
<!-- /xref -->

## Limits

- The mapping is supplied by the caller, so it is marked synthetic and its
  base unverified; a wrong maps file gives wrong attributions.
- Call chains are taken as `perf` recorded them; xref does not unwind them
  again.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
