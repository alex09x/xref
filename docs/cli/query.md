# xref query

Run one versioned JSON query and print a JSON response. This is the same
interface the MCP server exposes, for scripts and agents that prefer one
process per question. Operations: `info`, `strings`, `refs`, `function`,
`calls`, `callers`, `call_context`, `investigate`, `field_origin`,
`symbolize`, `asm`, `c`, `field`, `slice`. Request shapes and limits:
[Structured queries and local MCP](../mcp.md).

## Usage

<!-- xref:usage query -->
```text
xref query <REQUEST>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options query -->
**Arguments**

| Option | Description | Default |
| --- | --- | --- |
| `<REQUEST>` | The request as one JSON object, e.g. `{"operation":"info"}`. |  |
<!-- /xref -->

## Examples

### Image identity

<!-- xref:run -->
```console
$ xref -b rg query '{"operation":"info"}'
```

```text output
{"build_revision":null,"data":{"functions":8345,"imports":0,"kind":"info","pointers":21594,"segments":2,"symbols":0},"error":null,"image":{"architecture":"x86_64","base_address":"0x0","bytes":6597984,"format":"elf","rva_basis":"lowest_load_segment_va","sha256":"f401154e2393f9002ac77e419f9ee5521c18f4f8cd3e32293972f493ba06fce7"},"operation":"info","page":null,"schema_version":1,"tool":"xref","tool_version":"0.4.0","warnings":[]}
```
<!-- /xref -->

Every response has `schema_version`, the tool version and build revision, the
image identity (`sha256`, format, architecture, base address), `data`,
`error`, `warnings` and `page`.

### An invalid request

<!-- xref:run -->
```console
$ xref -b rg query '{"operation":"nope"}'
```

```text output
{"build_revision":null,"data":null,"error":{"code":"invalid_request","message":"unknown variant `nope`, expected one of `info`, `strings`, `refs`, `function`, `calls`, `callers`, `call_context`, `investigate`, `field_origin`, `symbolize`, `asm`, `c`, `field`, `slice` at line 1 column 19"},"image":null,"operation":"invalid_request","page":null,"schema_version":1,"tool":"xref","tool_version":"0.4.0","warnings":[]}
```

Exit status 1.
<!-- /xref -->

Errors are JSON too (`error.code`, `error.message`, which lists the valid
operations) and the exit status is non-zero.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
