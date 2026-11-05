# xref tree

Indented caller or callee tree of a function, with ranges and first panic locations.

Finds shortest call chains between two functions and prints indented caller/callee trees annotated with panic source locations.

## Usage

<!-- xref:usage tree -->
```text
xref tree [OPTIONS] <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options tree -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` |  |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--callers` | Show callers instead of callees. |  |
| `--callees` | Show callees (default). |  |
| `--depth <DEPTH>` | Maximum tree depth. | `3` |
| `--with-observed <WITH_OBSERVED>` |  |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Tree 0xd0aa0 --callers --depth 2

2-hop upward caller tree from 0xd0aa0 across loops.rs -> unrotate.rs -> cfg.rs.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped tree 0xd0aa0 --callers --depth 2
```

```text output
0xd0aa0..0xd0d73  src/loops.rs:33:18
  0xc7fc0..0xd0a9d  at 0xcbe5e x2  src/unrotate.rs:133:22
    0xb43a0..0xbb5da  at 0xb6793  src/cfg.rs:169:44
```

```stderr
xref: load 510.1µs, total 3.0ms
```
<!-- /xref -->

### Tree 0x9ef60 --callees --depth 2

2-hop downward callee tree rooted at 0x9ef60.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped tree 0x9ef60 --callees --depth 2
```

```text output
0x9ef60..0x9f518  src/image.rs:46:20
  0x131ec0..0x131f23  at 0x9f17c
    0x129030..0x12916c  at 0x131ef5
    0x1267c5..0x1267d8  at 0x131f1e
  0x86340..0x863bd  at 0x9f300
    0xa6aa0..0xa6bfc  at 0x86388
    0x1267c5..0x1267d8  at 0x863a9 x2
  0x15fe80..0x15ff45  at 0x9f366
    0x15e180..0x15e1ab  at 0x15fec2 x3
  0x6d5e0..0x6d735  at 0x9f50e
    0x85920..0x8633f  at 0x6d730
```

```stderr
xref: load 486.6µs, total 2.6ms
```
<!-- /xref -->

## Reading the output

- The root line is the function and its first panic location; each indented line is a caller (with `--callers`) or callee, the call site (`at …`, `x2` when there are several) and its first panic location.
- `--depth` sets how many levels are expanded.

## Limits

- Only direct calls, tail jumps and visible pointer slots are followed.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2; `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
