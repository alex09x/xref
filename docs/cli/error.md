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
| `<TEXT>` | Text (or part of it) the variant's message contains. |  |

**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--back <BACK>` | Also accept references this many bytes before the text (rustc format pieces start with a length byte). | `1` |
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
xref: load 634.8µs, total 3.5ms
```
<!-- /xref -->

## Reading the output

- One line per code reference to the text: where it is used, the function, the enum variant indices whose jump-table arm leads there, the table (with its dispatch instruction and arm count) and the arm.
- The last line counts the references.

## Limits

- Only `Display`/`match` code compiled to jump tables is resolved; a variant mapped through `if` chains or a lookup table gives no variant index.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `xref.stripped` = a stripped xref build (the binary of the home-page examples). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
