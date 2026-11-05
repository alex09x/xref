# xref src

Rust source locations (panic `Location`s) the function containing an address passes.

Extracts core::panic::Location structs from .rodata even after strip --strip-all, linking stripped functions back to exact file:line:col anchors.

## Usage

<!-- xref:usage src -->
```text
xref src <ADDR>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options src -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<ADDR>` | An address inside the function. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Src 0xfbff0

Lists every panic Location struct passed inside stripped function 0xfbff0..0xfc159.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped src 0xfbff0
```

```text output
function 0xfbff0..0xfc159
0xfc120  src/cfg.rs:75:25
0xfc132  src/cfg.rs:89:107
0xfc147  src/cfg.rs:95:29
3 locations
```

```stderr
xref: load 524.0µs, total 1.4ms
```
<!-- /xref -->

### Src

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped src 0xc7d60
```

```text output
function 0xc7d60..0xc7fbf
0xc7faa  src/loops.rs:45:36
1 locations
```

```stderr
xref: load 470.0µs, total 1.3ms
```
<!-- /xref -->

### Src

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped src 0x9a8a0
```

```text output
function 0x9a8a0..0x9a97a
0x9a947  src/cfg.rs:154:22
0x9a959  src/cfg.rs:75:25
0x9a96b  src/cfg.rs:154:57
3 locations
```

```stderr
xref: load 518.9µs, total 1.5ms
```
<!-- /xref -->

### Src

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped src 0xa2270
```

```text output
function 0xa2270..0xa2566
0xa2548  src/image.rs:184:58
1 locations
```

```stderr
xref: load 518.1µs, total 1.5ms
```
<!-- /xref -->

## Reading the output

- The first line is the function range; each following line is an instruction that passes a panic `Location` and the `file:line:column` it names. The last line counts them.

## Limits

- Only locations passed to panic paths are known; they point to where a bounds check or `unwrap` was written, which can be inlined code from another file.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
