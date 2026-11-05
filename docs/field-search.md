# Field key search and writer ranking

Search a stripped executable for a set of serialized keys and rank candidate
writers with:

```sh
xref -b ./app field --keys c,m,e --write --writes-all-of m,e --json
```

`--writes-all-of` retains candidates with observed writes covering every
named field on one tracked input root. Wide writes can cover multiple fields.
The result remains an instruction-based candidate, not proof of a concrete
source type or object lifetime. `--min-keys N` permits partial key matches;
without it the requested key set remains exact. Keys emitted only inside the
value of a requested key (for example `nanos` of an `elapsed: Duration` field)
stay in the layout output but do not count against the exact set. `--max-functions` and
`--max-instructions` set bounded analysis limits.

The fast seed intersection follows known direct calls. If it excludes partial
key-reference seeds, coverage reports `key_seed_filter_excluded` and an
incomplete-analysis warning: indirect or unresolved calls could connect those
seeds. Use `--exhaustive-key-seeds` to include them under the configured
function budget. This can take longer and may still be limited by the budget.

Before applying `--limit`, writer candidates are ranked using the number of
field offsets written in the same basic block and the shortest undirected
direct-call distance, up to six edges, from the inferred serializer. Stores that
start at a field and are no wider than its observed reads count extra (more so
when they cover every layout field), as does a field compared before it is
written (an update such as `cmp r, [p+0x10]` then `mov [p+0x10], r`). Wide stores that span several fields (`movups`) look like
whole-struct copies and get no such credit, and neither does a root whose
queried slot is loaded and then dereferenced in the same function, because that
slot holds a pointer (for example a `Vec` `{cap, ptr, len}`). The JSON fields
`colocated_written_fields`, `callgraph_distance` and `ranking_score` show the
evidence. Unknown or indirect call relationships have no distance; the rank is
a heuristic, not proof that two functions handle the same object.

`--writer-root returned|argument|loaded` keeps only writers whose offsets are
relative to that kind of pointer. Use `returned` for a struct reached through
a pointer returned by a call, such as a map lookup:

```sh
xref -b ./app field --keys c,m,e --write --writes-all-of m,e --writer-root returned
```

Offset constellations like `0, 8, 16` are common (a `Vec` has the same shape),
so on a large binary a writer through a lookup result can rank below many
argument-relative candidates near the serializer; restricting the root removes
them.

For whole-image searches, XRef builds a reusable index of static references,
direct calls and writer facts. It stores private cache files below
`$XDG_CACHE_HOME/xref/field-index-v1`, or `~/.cache/xref/field-index-v1` when
`XDG_CACHE_HOME` is unset. The cache includes instruction text and addresses,
is keyed by the input and XRef executable contents, and is rebuilt after a
change or corruption. Files are limited to 256 MiB each; old files are not
automatically evicted. Delete that directory to clear them. A scoped `--within`
search does not use the persistent index. Coverage fields report cache hits,
prefiltered functions and analysis limits. The first search must build the
index; later searches can reuse it with different key sets and writer filters.

For many queries over one binary, run the MCP server (`xref -b ./app mcp`) and
send `xref_query` requests with `{"operation": "field", "request": {...}}`. The
request takes `keys`, `write`, `writes_all_of`, `writer_root`, `limit` (default
16), `min_keys`, `min_offsets`, `max_functions`, `max_instructions`,
`layout_only` and `exhaustive_key_seeds`, and returns the same JSON report as
`field --json`. The server keeps the image digest, the whole-image scan and
call graph, the writer index and analyzed functions in memory, so after the
first queries a new key set or filter costs only key matching, context
selection and ranking, without the image load and whole-image scan a fresh
CLI run repeats. The server starts building this state (including the writer
index, when the on-disk cache is empty) in the background as soon as it starts.
Queries never wait for that warm-up: once it has finished they reuse the
prepared state, and before then they take the ordinary path. The warm-up is
bounded by the analysis budget and may not complete on every input.

On Unix, after a `field` run on an input of at least 16 MiB that takes longer
than 250 ms, the CLI starts a background `xref -b BIN field-daemon` for that binary. It keeps the image and
the field session in memory behind a private socket in
`./field-index-v1/daemon/`, and later `xref field` runs for the same
unchanged binary and xref executable are answered by it without reloading the
image (stderr says `field daemon`). It re-checks the input and
executable metadata before every request and exits when either changed or
after `XREF_FIELD_DAEMON_IDLE_SECS` (default 900) without requests.
`XREF_NO_DAEMON=1` disables it.

A repeated `field` command with exactly the same arguments on an unchanged
input replays the stored report from `.../field-index-v1/results` without
loading or hashing the image.
The key covers every argument, the canonical input path and its device, inode,
size, modification and change times, and the same metadata of the xref
executable. Reports that hit the 30-second analysis budget are not stored. Set
`XREF_NO_RESULT_CACHE=1` to bypass it. A query with different arguments runs
the search again; the selected context functions are analysed in parallel.

For a repeatable Linux x86-64 stress case, the repository can generate a
neutral ELF with 65,000 additional functions. The `--writers` variant makes
each of them write the same two offsets, stressing ranking before the limit:

```sh
python3 tests/fixtures/field_perf/generate.py /tmp/xref-field-perf --writers
cc -O2 -g0 -fno-inline -fno-ipa-icf /tmp/xref-field-perf/target.c /tmp/xref-field-perf/bulk.S -o /tmp/xref-field-perf/target
objcopy --strip-all /tmp/xref-field-perf/target /tmp/xref-field-perf/target-stripped
xref -b /tmp/xref-field-perf/target-stripped field --keys c,m,e --write --writes-all-of m,e --limit 1
```

Run the last command twice to distinguish index construction from reuse. The
generated code is synthetic and timings do not predict performance for every
real binary.
