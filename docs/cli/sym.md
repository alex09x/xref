# xref sym

List function symbols whose name contains a pattern. Useful only on binaries
that still carry a symbol table; stripped release binaries have none (use
[`refs`](refs.md), [`where`](where.md) or [`find`](find.md) there).

## Usage

<!-- xref:usage sym -->
```text
xref sym <PATTERN>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options sym -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<PATTERN>` | Substring of the raw (mangled) symbol name. |  |
<!-- /xref -->

## Examples

### Find a function by part of its name

The xref 0.4.0 release binary is not stripped, so its Rust symbols (mangled
`_RNv…` names) can be searched:

<!-- xref:run -->
```console
$ xref -b xref-0.4.0 sym field_by_keys
```

```text output
0x355940  _RNvNtCs1SrNGm53fEm_4xref12serde_fields13field_by_keys
1 symbols
```

```stderr
xref: load 5.0ms, total 5.1ms
```
<!-- /xref -->

Each line is the function start address and its raw linker name; the last line
counts the matches. Pass the address to [`c`](c.md), [`asm`](asm.md) or
[`card`](card.md).

### On a stripped binary

<!-- xref:run -->
```console
$ xref -b rg sym main
```

```text output
0 symbols
```

```stderr
xref: load 3.8ms, total 3.8ms
```
<!-- /xref -->

A stripped binary has no symbol table, so nothing is found.

## Limits

- Names are matched as raw bytes of the linker symbol (mangled for Rust and
  C++), not demangled.
- Only symbols that the image keeps are searched; stripped binaries return none.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
