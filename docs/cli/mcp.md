# xref mcp

Serve a read-only MCP server over stdio for one binary. An agent (Claude Code,
Codex, any MCP client) gets the `xref_query` tool with the same operations as
[`query`](query.md), against one immutable image identified by its SHA-256.
With `--allow-live-pid PID` it also gets the opt-in `xref_live` tool, pinned to
that verified process.

## Usage

<!-- xref:usage mcp -->
```text
xref mcp [OPTIONS]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options mcp -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--allow-live-pid <PID>` | Explicitly enable the PID-bound `xref_live` MCP tool for this single verified Linux process. |  |
<!-- /xref -->

## Configure a client

```json
{
  "mcpServers": {
    "xref": { "command": "xref", "args": ["-b", "/path/to/binary", "mcp"] }
  }
}
```

The server reads JSON-RPC from stdin and writes responses to stdout; it never
writes anything else to stdout. For `field` it keeps the image, the whole-image
scan and the writer index in memory, so later queries reuse them.

Request shapes, budgets, pagination and errors:
[Structured queries and local MCP](../mcp.md).

## Limits

- One binary per server process; start another server for another binary.
- `xref_live` exists only with `--allow-live-pid`, on Linux x86-64.
