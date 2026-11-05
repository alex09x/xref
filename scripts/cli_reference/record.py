#!/usr/bin/env python3
# XRef — refresh the generated parts of the command reference pages (docs/cli/*.md)
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run the examples written in docs/cli/*.md with a given xref binary and write their output back.

    record.py --xref ./xref --inputs DIR [PAGE.md ...]

The Markdown pages are the only source. Hand-written prose is kept; these blocks are rewritten:

    <!-- xref:usage refs -->     ... <!-- /xref -->   usage line from `xref refs --help`
    <!-- xref:options refs -->   ... <!-- /xref -->   arguments and options from `xref refs --help`
    <!-- xref:run max=40 -->     ... <!-- /xref -->   the block's first `$ xref ...` command, run in DIR;
                                                      its stdout and stderr replace the rest of the block
    <!-- xref:provenance -->     ... <!-- /xref -->   tool, host and input binaries

Examples run in DIR, which holds the public input binaries listed in INPUTS. Never point an example
at a private binary: the output is published.
"""

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "docs" / "cli"
INPUTS = {
    "rg": "`rg` = ripgrep 14.1.1 (official stripped release)",
    "xref.stripped": "`xref.stripped` = a stripped xref build (the binary of the home-page examples)",
    "xref-v0.0.2.stripped": "`xref-v0.0.2.stripped` = stripped xref 0.0.2",
    "xref-0.4.0": "`xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped)",
}
BLOCK = re.compile(r"(<!-- xref:(usage|options|run|provenance)([^>]*?) -->\n)(.*?)(<!-- /xref -->)", re.S)
ENTRY = re.compile(r"^ {2,6}(?:(-[A-Za-z0-9])(?:, |$|(?=\s)))?(--[A-Za-z0-9-]+)?((?:\s?[<\[][^\]>]+[>\]](?:\.\.\.)?)*)(?:\s{2,}(.*))?$")
ARG = re.compile(r"^  ([<\[][^\]>]+[>\]](?:\.\.\.)?)(?:\s{2,}(.*))?$")


def parse_help(text):
    """Split clap help into (usage, [(section, [entry])]); entry = {flag, short, value, text, default, env, values}."""
    lines = text.splitlines()
    usage = next((l[len("Usage: "):] for l in lines if l.startswith("Usage: ")), "")
    sections, current = [], None
    for line in lines:
        if line in ("Arguments:", "Options:"):
            current = (line[:-1], [])
            sections.append(current)
            continue
        if line.startswith("Commands:"):
            current = None
        if current is None:
            continue
        indent = len(line) - len(line.lstrip(" "))
        arg = ARG.match(line) if current[0] == "Arguments" else None
        opt = ENTRY.match(line) if current[0] == "Options" and indent <= 6 and line.lstrip().startswith("-") else None
        if arg:
            current[1].append({"flag": arg.group(1), "short": None, "value": "", "text": [arg.group(2) or ""], "values": []})
        elif opt:
            current[1].append({"flag": opt.group(2) or opt.group(1), "short": opt.group(1) if opt.group(2) else None,
                               "value": (opt.group(3) or "").strip(), "text": [opt.group(4) or ""], "values": []})
        elif current[1] and line.strip():
            entry, body = current[1][-1], line.strip()
            if body == "Possible values:":
                entry["in_values"] = True
            elif entry.get("in_values") and body.startswith("- "):
                entry["values"].append(body[2:])
            else:
                entry["text"].append(body)
    for _, entries in sections:
        for entry in entries:
            text = " ".join(t for t in entry.pop("text") if t).strip()
            entry.pop("in_values", None)
            default = re.search(r"\[default: ([^\]]+)\]", text)
            env = re.search(r"\[env: ([^\]]+)\]", text)
            entry["default"] = default.group(1) if default else None
            entry["env"] = env.group(1).rstrip("=") if env else None
            entry["text"] = re.sub(r"\s*\[(default|env): [^\]]+\]", "", text).strip()
    return usage, sections


def options_md(help_text):
    _, sections = parse_help(help_text)
    cell = lambda s: s.replace("|", "\\|")  # noqa: E731
    out = []
    for name, entries in sections:
        entries = [e for e in entries if e["flag"] not in ("--help", "--version")]
        if not entries:
            continue
        out += [f"**{name}**", "", "| Option | Description | Default |", "| --- | --- | --- |"]
        for e in entries:
            flag = (f"`{e['short']}`, " if e["short"] else "") + f"`{e['flag']}" + (f" {e['value']}`" if e["value"] else "`")
            text = e["text"] if not e["text"] or e["text"].endswith(".") else e["text"] + "."
            if e["values"]:
                pairs = [value.partition(":") for value in e["values"]]
                text += " Values: " + "; ".join(f"`{k.strip()}`" + (f" ({d.strip()})" if d else "") for k, _, d in pairs) + "."
            if e["env"]:
                text += f" Environment: `{e['env']}`."
            default = f"`{e['default']}`" if e["default"] else ""
            out.append(f"| {cell(flag)} | {cell(text)} | {cell(default)} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def run_example(xref, cmd, inputs, limit, start=None, timeout=300):
    argv = shlex.split(cmd)
    assert argv[0] == "xref", f"examples must start with `xref`: {cmd}"
    proc = subprocess.run([str(xref), *argv[1:]], cwd=inputs, capture_output=True, text=True, timeout=timeout)
    trim = lambda s: "\n".join(l.rstrip() for l in s.rstrip("\n").split("\n")) if s.strip() else ""  # noqa: E731
    stdout, stderr = trim(proc.stdout), trim(proc.stderr)
    sub = argv[3] if len(argv) > 3 and argv[1] == "-b" else (argv[1] if len(argv) > 1 else "")
    lang = "c" if sub in ("c", "decomp") else "asm" if sub == "asm" else "text"
    if "--json" in argv and stdout.startswith("{"):
        lang = "json"
    out = ["```console", f"$ {cmd}", "```", ""]
    lines = stdout.split("\n") if stdout else []
    if lines:
        first = 0
        if start:
            first = next((i for i, line in enumerate(lines) if re.search(start, line)), None)
            if first is None:
                raise ValueError(f"no stdout line matches from={start!r} in: {cmd}")
        shown = lines[first : first + limit]
        if first:
            out.append(f"*First {first} lines omitted; shown from the first line matching `{start}`.*")
            out.append("")
        out += [f"```{lang} output", *shown, "```"]
        if first + len(shown) < len(lines):
            out.append(f"*Output cut here: lines {first + 1}–{first + len(shown)} of {len(lines)} shown.*")
        out.append("")
    else:
        out += ["*(no stdout)*", ""]
    if proc.returncode:
        out += [f"Exit status {proc.returncode}.", ""]
    if stderr:
        out += ["```stderr", stderr, "```", ""]
    return "\n".join(out)


def provenance(xref, inputs, note):
    version = subprocess.run([str(xref), "--version"], capture_output=True, text=True).stdout.strip()
    used = [desc for name, desc in INPUTS.items() if (inputs / name).exists()]
    out = [f"Recorded with {note or version} on Linux x86-64, on "
           + "; ".join(used) + ". Output is unchanged; long outputs are cut where marked."]
    return "\n".join(out) + "\n"


def refresh(page, xref, inputs, note):
    text = page.read_text(encoding="utf-8")
    helps = {}

    def help_of(command):
        if command not in helps:
            helps[command] = subprocess.run([str(xref), *command.split(), "--help"], capture_output=True, text=True).stdout
        return helps[command]

    def fill(m):
        kind, arg = m.group(2), m.group(3).strip()
        if kind == "usage":
            usage, _ = parse_help(help_of(arg))
            usage = re.sub(r"^\S+", "xref", usage)
            body = f"```text\n{usage}\n```\n"
        elif kind == "options":
            body = options_md(help_of(arg))
        elif kind == "run":
            cmd = re.search(r"^\$ (xref .+)$", m.group(4), re.M)
            if not cmd:
                raise ValueError(f"{page.name}: xref:run block without a `$ xref ...` command")
            limit = int(re.search(r"max=(\d+)", arg).group(1)) if "max=" in arg else 40
            start = re.search(r'from="([^"]+)"', arg)
            body = run_example(xref, cmd.group(1), inputs, limit, start.group(1) if start else None)
            print(f"{page.name}: {cmd.group(1)}", file=sys.stderr)
        else:
            body = provenance(xref, inputs, note)
        return m.group(1) + body + m.group(5)

    page.write_text(BLOCK.sub(fill, text), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--xref", required=True, help="xref binary to record with (its file name should be `xref`)")
    ap.add_argument("--inputs", required=True, help="directory holding the public input binaries")
    ap.add_argument("--note", default="", help="extra provenance note, e.g. the source commit")
    ap.add_argument("pages", nargs="*", help="pages to refresh (default: every docs/cli/*.md)")
    args = ap.parse_args()
    xref, inputs = Path(args.xref).resolve(), Path(args.inputs).resolve()
    for page in [Path(p) for p in args.pages] or sorted(CLI.glob("*.md")):
        refresh(page, xref, inputs, args.note)


if __name__ == "__main__":
    main()
