# xref error

Enum variant whose `Display`/`match` arm names a text: the jump-table index of the referencing arm.

Resolves relative jump tables into variant arm ranges, string literals per arm, reverse instruction-to-arm ownership, and constant error returns.

## Usage

<!-- xref:usage error -->
```text
xref error [OPTIONS] <TEXT>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options error -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<TEXT>` |  |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--back <BACK>` |  | `1` |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Error 13

Finds return/assign sites setting a specific constant code and their enclosing jump-table variants.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped error 13
```

```text output
0xf02b8  in 0xd7740  variant 2 (0x2), 5 (0x5)  table 0xc338 (dispatch 0xe11de, 6 arms)  arm 0xe1278
0xf03c6  in 0xd7740  variant 2 (0x2), 5 (0x5)  table 0xc338 (dispatch 0xe11de, 6 arms)  arm 0xe1278
2 references
```

```stderr
xref: load 508.0µs, total 3.1ms
```
<!-- /xref -->

## Reading the output

- One line per code reference to the text: where it is used, the function, the enum variant indices whose jump-table arm leads there, the table (with its dispatch instruction and arm count) and the arm.
- The last line counts the references.

## Limits

- Only `Display`/`match` code compiled to jump tables is resolved; a variant mapped through `if` chains or a lookup table gives no variant index.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2; `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
