# xref live resolve

Translate addresses between the binary on disk and a running process: a
static address (as printed by every static command) becomes the runtime
address in this process, and a runtime address (from a debugger, a crash log,
`perf`) becomes the static one. The translation uses the verified PIE slide
and the `PT_LOAD` segments.

## Usage

<!-- xref:usage live resolve -->
```text
xref live resolve [OPTIONS] --pid <PID> <ADDR>...
```
<!-- /xref -->

## Arguments and options

<!-- xref:options live resolve -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>...` | Static or live runtime addresses (`0x...` hex or decimal). |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--pid <PID>` | Target process ID (must be non-zero). |  |
| `--force-bin` | Continue even if `--bin` does not match `/proc/<pid>/exe`. |  |
| `--json` | Emit structured `schema_version: 1` JSON output. |  |
<!-- /xref -->

## Examples

The target is ripgrep 14.1.1 (`rg`) filtering an endless input stream, as on
[`live maps`](live-maps.md). PIDs and runtime addresses belong to that run.

### Static to runtime

`0x10b0c0` is one of ripgrep's hottest functions in the
[profile](live-profile.md):

<!-- xref:run -->
```console
$ xref -b rg live resolve --pid 4060909 0x10b0c0
```

```text output
pid 4060909  starttime 1480802351  match verified_sha256  pie_slide +0x77d9cd600000  alive true  changed false
0x10b0c0  static_to_runtime  static 0x10b0c0  runtime 0x77d9cd70b0c0  file 0x10b0c0  sym -  /home/alex09x/xref-docs/rg+0x10b0c0
```
<!-- /xref -->

## Reading the output

- After the identity header, one line per address: the direction
  (`static_to_runtime` or `runtime_to_static`), both addresses, the file
  offset, the symbol if the binary has one, and `module+offset`.

## Limits

- Addresses outside the executable's mappings (shared libraries, heap) have
  no static counterpart and are reported as such.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Live examples ran against one ripgrep process filtering an endless input stream; commands shown with `sudo` ran as root. Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
