# XRef — Live Analysis walkthrough: parsers for recorded human-readable xref stdout
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Small, strict parsers over `xref` human-readable output used to chain walkthrough steps."""

import re

_HIT = re.compile(r"^hit (0x[0-9a-f]+)\s+(\S.*)$")
_ROW = re.compile(r"^\s*([+-]?0x[0-9a-f]+)\*?\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+|\?+)\s+(\S+)\s*(.*)$")
_FN = re.compile(r"\bfn (0x[0-9a-f]+)\+0x0\b")
_REF = re.compile(r"^0x[0-9a-f]+\s+in (0x[0-9a-f]+)\s")


def heap_hit_rows(stdout):
    """Context rows of the first memscan hit located in `[heap]`."""
    rows, active = None, False
    for line in stdout.splitlines():
        hit = _HIT.match(line)
        if hit:
            if rows is not None:
                break
            active = hit.group(2).startswith("[heap]")
            if active:
                rows = []
            continue
        row = _ROW.match(line)
        if active and row:
            rows.append({"off": row.group(1), "va": row.group(2), "value": row.group(3), "kind": row.group(4),
                         "detail": row.group(5).strip()})
    if not rows:
        raise SystemExit(f"no [heap] memscan hit in:\n{stdout}")
    return rows


def row_at(rows, off):
    for row in rows:
        if row["off"] == off:
            return row
    raise SystemExit(f"memscan context has no row at {off}: {[r['off'] for r in rows]}")


def static_fn_of(row):
    """Static function start of a `code_ptr` context row (`fn 0x...+0x0`)."""
    found = _FN.search(row["detail"])
    if row["kind"] != "code_ptr" or not found:
        raise SystemExit(f"expected an exact code_ptr function start, got {row}")
    return found.group(1)


def static_of_resolved(stdout, runtime_va):
    """Static VA printed by `xref live resolve` for one runtime address."""
    want = int(runtime_va, 16)
    for line in stdout.splitlines():
        found = re.match(r"^(0x[0-9a-f]+)\s+runtime_to_static\s+static (0x[0-9a-f]+)\s", line)
        if found and int(found.group(1), 16) == want:
            return found.group(2)
    raise SystemExit(f"resolve output has no runtime_to_static row for {runtime_va}:\n{stdout}")


def first_ref_function(stdout):
    """Function containing the first code reference printed by `xref refs`."""
    for line in stdout.splitlines():
        ref = _REF.match(line)
        if ref:
            return ref.group(1)
    raise SystemExit(f"no code reference in:\n{stdout}")
