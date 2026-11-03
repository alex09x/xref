# XRef — Live Analysis walkthrough: narrative checked against the recorded transcript
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Walkthrough sections. Every claim that depends on the run is read from the transcript and
asserted, so a re-recording that behaves differently fails loudly instead of publishing stale text."""

import json
import re

from parse import heap_hit_rows, row_at


def _step(doc, step_id):
    for step in doc["steps"]:
        if step["id"] == step_id:
            return step
    raise SystemExit(f"transcript has no step {step_id!r}")


def _expect(cond, what):
    if not cond:
        raise SystemExit(f"recording no longer matches the walkthrough text: {what}")


def _ready(step):
    for line in step["stderr"].splitlines():
        if "_ready " in line:
            return json.loads(line.split("_ready ", 1)[1])
    raise SystemExit(f"{step['id']}: no ready receipt")


def _probes(stdout):
    found = re.findall(r"^probe static (0x[0-9a-f]+) .* hits (\d+)$", stdout, re.M)
    return {addr: int(hits) for addr, hits in found}


def _callers(stdout):
    return re.findall(r"^  caller ra \S+ \(static \S+\)\s+fn (0x[0-9a-f]+)\s+call_site (0x[0-9a-f]+)\s+verified (\w+)",
                      stdout, re.M)


def _field(line_re, stdout, what):
    found = re.search(line_re, stdout, re.M)
    _expect(found, what)
    return found


def sections(doc):
    d = doc["derived"]
    hook, dep = d["hook_fn"], d["deposit_fn"]
    pid = doc["pid"]
    maps = _step(doc, "maps")["stdout"]
    summary = maps.strip().splitlines()[-1]
    match = _field(r"match (\S+)\s+pie_slide (\S+)", maps, "maps header").groups()
    _expect(match[0] == "verified_build_id", "maps should verify the -b binary by build-id")

    scan = _step(doc, "memscan")["stdout"]
    rows = heap_hit_rows(scan)
    _expect(row_at(rows, "+0x18")["value"].endswith("309") and row_at(rows, "+0x20")["value"].endswith("7a120"),
            "heap vault should hold account 777 and balance 500000")
    _expect(row_at(rows, "+0x38")["kind"] == "code_ptr", "vault +0x38 should be a code pointer")
    bss = _field(r"^hit (0x[0-9a-f]+)\s+(/\S+\+0x[0-9a-f]+)$", scan, ".bss hit").group(2)

    probe = _step(doc, "probe")["stdout"]
    hits = _probes(probe)
    _expect(hits.get(dep) == 2 and hits.get(hook) == 1, f"probe counts {hits}")
    callers = _callers(probe)
    hook_callers = [c for c in callers if c[0] == dep]
    _expect(hook_callers and hook_callers[0][2] == "true", "hook caller should be the verified deposit handler")
    dispatcher = [c for c in callers if c[0] != dep][0]
    for reg in ("rsi 0x309", "rdx 0x3d090", "rdx 0x1e848", "rdi 0xb71b0", "rsi 0x420042"):
        _expect(reg in probe, f"probe registers should contain {reg}")

    watch = _step(doc, "watch")["stdout"]
    w = _field(r"^  writer (0x[0-9a-f]+) \(trap \S+ / static (0x[0-9a-f]+)\)\s+fn (0x[0-9a-f]+) .*insn \"([^\"]+)\"\s+conf (\S+)",
               watch, "watch writer")
    latest = _field(r"latest (0x[0-9a-f]+)", watch, "watch latest").group(1)
    values = re.findall(r"value candidate_reg:\w+\(8B\)=(0x[0-9a-f]+)", watch)
    _expect(w.group(3) == dep and values and values[-1] == latest, "watch writer/value should match the deposit handler")

    rich = heap_hit_rows(_step(doc, "memscan_rich")["stdout"])
    follow_step = _step(doc, "follow")
    initial_leaf = _ready(follow_step)["watches"][1]
    f = _field(r"^follow ptr_slot \S+\s+state (\S+)\s+gen (\d+)\s+leaf (0x[0-9a-f]+)\s+slots \d+\s+root_hits (\d+)\s+leaf_hits (\d+)",
               follow_step["stdout"], "follow summary")
    _expect(f.group(1) == "bound" and int(f.group(2)) >= 2 and int(f.group(3), 16) != int(initial_leaf, 16),
            "follow should end bound at a relocated leaf")

    return [
        {
            "id": "target", "title": "Start a stripped program and give it some state",
            "lead": [
                "The target is our own fixture, [`tests/fixtures/live_daemon_app.rs`](https://github.com/alex09x/xref/blob/main/tests/fixtures/live_daemon_app.rs), "
                "built with `-C strip=symbols`: no symbols, no debug info. It keeps a vault structure on the heap and changes it "
                "when it reads commands such as `DEPOSIT`, `ROTATE` and `VEC_MOVE_WRITE0` on stdin. "
                "We act as if we knew only one thing about it: the 16-byte signature `DAEMONV2` + `0x778899aabbccddee` "
                "that it keeps at the start of the vault.",
            ],
            "terminal": [("$ ./vault-daemon", doc["banner"])] + [(f"> {io['send']}", io["reply"]) for io in doc["start_io"]],
        },
        {
            "id": "maps", "title": "Confirm the process and the binary", "step": "maps",
            "lead": ["`xref live maps` reads `/proc/<pid>/maps` and `smaps`, checks that the file passed with `-b` is the "
                     "executable that is running, and computes the PIE slide that links runtime addresses to static ones."],
            "notes": [
                f"`match {match[0]}`: the ELF given to `-b` has the same GNU build-id as `/proc/{pid}/exe`, so static "
                "analysis of that file applies to this process.",
                f"`pie_slide {match[1]}`: runtime address = static address + slide (for this run only; ASLR changes it every start).",
                f"`{summary}`: only private writable mappings are searched later. Shared, device and other file-backed "
                "writable mappings are skipped and listed with the reason.",
            ],
        },
        {
            "id": "memscan", "title": "Find the structure in memory", "step": "memscan",
            "lead": ["`xref live memscan` searches the scannable regions for the two signature words and prints a window of "
                     "8-byte words around each hit. Every word is classified against the static image: code pointer, "
                     "pointer to a string, heap pointer, vtable candidate or plain number."],
            "notes": [
                f"Two hits. `{bss}` is inside the binary's own writable segment (a global mirror of the vault). "
                "The `[heap]` hit is the live vault, read below.",
                "`+0x10 = 1` is a sequence counter, `+0x18 = 0x309` is account 777, `+0x20 = 0x7a120` is the 500000 we "
                "just deposited, `+0x28` holds a derived value, `+0x30 = 0x420042` looks like a key.",
                f"`+0x38` is a `code_ptr`: the structure stores a function pointer to static function `{hook}`.",
                "`+0x40` points to the text `XREF_DAEMON_VAULT_ACTIVE_V2`; `+0x48` points to another heap object; `+0x50` "
                "points into read-only relocated data with two candidate functions, the usual shape of a Rust trait-object vtable.",
                "`+0x60` points to a static string. Rust string literals are not NUL-terminated, so the preview runs into the "
                "next literal. Use the address, not the preview text.",
            ],
        },
        {
            "id": "resolve", "title": "Translate the two pointers to static addresses", "step": "resolve",
            "lead": ["`xref live resolve` turns runtime addresses into static addresses and file offsets of the verified binary. "
                     "The static addresses are what every static `xref` command takes."],
            "notes": [f"The function pointer is static function `{hook}`; the string pointer is static address `{d['label_va']}`."],
        },
        {
            "id": "refs", "title": "Find the code that stores that string", "step": "refs",
            "lead": ["Static analysis of the same stripped file: which instructions reference the string address?"],
            "notes": [f"Exactly one `lea`, inside function `{dep}`. That function writes the label into the vault, so it is "
                      "the code that handles deposits."],
        },
        {
            "id": "c_deposit", "title": "Read the deposit handler as pseudo-C", "step": "c_deposit",
            "lead": ["`xref c` decompiles the function directly from machine code."],
            "notes": [
                "The stores line up with the memory window from the memscan step: signature words at `+0` and `+8`, "
                "counter `+16` incremented, account at `+24`, amount added to `+32`, the result of an indirect call through "
                "the pointer at `+56` (`+0x38`) stored to `+40` (`+0x28`), then a call through the vtable at `+80` (`+0x50`).",
                "Four commands (`memscan`, `resolve`, `refs`, `c`) took us from one known value to the layout of the "
                "structure and the code that updates it.",
            ],
        },
        {
            "id": "c_hook", "title": "Read the function stored in the structure", "step": "c_hook",
            "lead": [f"The `code_ptr` from offset `+0x38` points to `{hook}`."],
            "notes": ["A small mixing function: the derived value at `+0x28` is computed from the balance and the key at `+0x30`."],
        },
        {
            "id": "probe", "title": "Count calls and see who makes them", "step": "probe", "sudo": True,
            "lead": [
                "`xref live probe` places Linux uprobes on the two static addresses, only for this process (`perf` backend). "
                "While it is armed we send three commands to the daemon: a deposit, a key rotation and another deposit.",
            ],
            "notes": [
                f"The deposit handler ran twice (`hits 2`), the stored function ran once (`hits 1`). `ROTATE` replaced the "
                "pointer at `+0x38`, so the second deposit called a different function.",
                f"Caller of the deposit handler: function `{dispatcher[0]}` at call site `{dispatcher[1]}` (the fixture's "
                f"command loop). Caller of `{hook}`: the deposit handler itself at `{hook_callers[0][1]}`, an indirect call "
                "through the structure field, matched by its return address.",
                "Registers at entry: `rsi 0x309` is account 777, `rdx 0x3d090` and `0x1e848` are the amounts 250000 and 125000. "
                "In the hook, `rdi 0xb71b0` is the new balance 750000 and `rsi 0x420042` is the key.",
                "The tags in brackets keep the limits visible: a return address can also come from a tail call, and register "
                "values do not prove source-level types.",
            ],
        },
        {
            "id": "watch", "title": "Catch the instruction that writes a field", "step": "watch", "sudo": True,
            "lead": ["`xref live watch` arms an x86 hardware write watchpoint (`DR0`–`DR3`) on the runtime address of the field "
                     "at `+0x28`, then we make two deposits."],
            "notes": [
                f"Both writes come from `{w.group(4)}` at static `{w.group(1)}` in function `{w.group(3)}`, the deposit handler "
                f"we decompiled. The CPU reports the trap after the store (`static {w.group(2)}`); xref names the preceding "
                f"store as the writer with confidence `{w.group(5)}`.",
                f"The value is decoded from the source register at the trap. The last sampled value equals `latest {latest}`, "
                "which xref read back from `/proc/<pid>/mem` after the window. The two agree, but a later snapshot alone "
                "would not prove what a store wrote.",
            ],
        },
        {
            "id": "memscan_rich", "title": "Find a growable buffer", "step": "memscan_rich",
            "lead": ["A second structure has its own signature (`XREFTYPE` + `0x1122334455667788`). It mirrors a `Vec<u64>`."],
            "notes": [
                f"`+0x50` is a heap pointer `{row_at(rich, '+0x50')['value']}` (the buffer), `+0x58` is the capacity, "
                "`+0x60` is the length. When the vector grows the program moves the buffer, so a watchpoint on a fixed "
                "address would go silent.",
            ],
        },
        {
            "id": "follow", "title": "Follow the buffer after it moves", "step": "follow", "sudo": True,
            "lead": [
                "`--follow` watches the pointer slot and the element it points to. `len_slot`/`min_len` and "
                "`guard_slot`/`guard_val` stop the watch if the length or the signature no longer match. We write element 0, "
                "move the buffer to a new allocation, and write element 0 again.",
            ],
            "notes": [
                f"At arm time the element was at `{initial_leaf}` (second address in the `watch_ready` line). After the move "
                f"the watch re-armed on the new buffer: `state bound`, `gen {f.group(2)}`, `leaf {f.group(3)}`.",
                f"`root_hits {f.group(4)}` is the write that published the new pointer, `leaf_hits {f.group(5)}` are writes to "
                "element 0 that were observed.",
                "Here the trap address is a branch target, so xref does not pick a single writer or value "
                "(`ambiguous_branch_target`, `unknown`). `(lower_bound)` marks the counts as a lower bound: a write "
                "made to the new buffer before its pointer is published happens before the watch can move.",
            ],
        },
    ]
