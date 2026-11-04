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
without it the requested key set remains exact. `--max-functions` and
`--max-instructions` set bounded analysis limits.

The fast seed intersection follows known direct calls. If it excludes partial
key-reference seeds, coverage reports `key_seed_filter_excluded` and an
incomplete-analysis warning: indirect or unresolved calls could connect those
seeds. Use `--exhaustive-key-seeds` to include them under the configured
function budget. This can take longer and may still be limited by the budget.

Before applying `--limit`, writer candidates are ranked using the number of
field offsets written in the same basic block and the shortest undirected
direct-call distance, up to six edges, from the inferred serializer. The JSON
fields `colocated_written_fields`, `callgraph_distance` and `ranking_score`
show the evidence. Unknown or indirect call relationships have no distance;
the rank is a heuristic, not proof that two functions handle the same object.

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
