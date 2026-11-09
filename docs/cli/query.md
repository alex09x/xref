# xref query

Run one versioned JSON query and print a JSON response. This is the same
interface the MCP server exposes, for scripts and agents that prefer one
process per question. Operations: `info` (with first-contact `triage`),
`strings`, `refs`, `function`, `calls`, `callers`, `call_context`,
`investigate`, `field_origin`, `symbolize`, `asm`, `c`, `field`, `slice`,
`dependencies`, `card`, `find`, `layout`, `files`, `where`, `origin`,
`callargs` and `data`. Every answer carries a `confidence` tier (`observed`,
`derived`, `inferred`) and a deterministic `evidence_id`. Request shapes and
limits: [Structured queries and local MCP](../mcp.md).

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
{"build_revision":"b00d4a14a24c2e3a723618f6c6069fd43ad9d548","confidence":"observed","data":{"functions":8345,"imports":0,"kind":"info","pointers":21594,"segments":2,"symbols":0,"triage":{"build_id":null,"high_entropy_executable":false,"language":"rust","panic_locations":2234,"recommended_queries":[{"reason":"map_recovered_rust_source_files","request":{"operation":"files","page":{"limit":50}}},{"reason":"summarize_largest_function_card","request":{"address":"0xf07b0","operation":"card"}},{"reason":"search_functions_by_multi_predicate_filter","request":{"operation":"find","page":{"limit":20},"size":"256..4096"}}],"source_files":268,"stripped":true,"toolchains":["GCC: (GNU) 9.4.0","rustc version 1.83.0-nightly (adf8d168a 2024-09-08)","GCC: (GNU) 9.2.0"]}},"error":null,"evidence_id":"ev_c086db0e57f575b1","image":{"architecture":"x86_64","base_address":"0x0","bytes":6597984,"format":"elf","rva_basis":"lowest_load_segment_va","sha256":"f401154e2393f9002ac77e419f9ee5521c18f4f8cd3e32293972f493ba06fce7"},"operation":"info","page":null,"schema_version":1,"tool":"xref","tool_version":"0.5.0","untrusted_binary_content":true,"warnings":[]}
```
<!-- /xref -->

Every response has `schema_version`, the tool version and build revision, the
image identity (`sha256`, format, architecture, base address), `data`,
`error`, `warnings` and `page`.

### An invalid request

<!-- xref:run exit=1 -->
```console
$ xref -b rg query '{"operation":"nope"}'
```

```text output
{"build_revision":"b00d4a14a24c2e3a723618f6c6069fd43ad9d548","confidence":null,"data":null,"error":{"code":"invalid_request","message":"unknown variant `nope`, expected one of `info`, `strings`, `refs`, `function`, `calls`, `callers`, `call_context`, `investigate`, `field_origin`, `symbolize`, `asm`, `c`, `field`, `slice`, `dependencies`, `card`, `find`, `layout`, `files`, `where`, `origin`, `callargs`, `data` at line 1 column 19"},"evidence_id":null,"image":null,"operation":"invalid_request","page":null,"schema_version":1,"tool":"xref","tool_version":"0.5.0","untrusted_binary_content":true,"warnings":[]}
```

Exit status 1.
<!-- /xref -->

Errors are JSON too (`error.code`, `error.message`, which lists the valid
operations) and the exit status is non-zero.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
