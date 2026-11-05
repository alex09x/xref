#!/usr/bin/env python3
# XRef — render the social preview card (Open Graph / X / GitHub) from a spec and a recorded example
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render a 1280x640 social preview PNG.

    render.py SPEC.json --out docs/og-vX.Y.Z.png [--html card.html] [--chrome PATH]

The terminal on the card is never typed by hand: it is the first `$ xref ...` command of the
example named in the spec, with the output recorded under it in docs/cli/<page>.md, cut to fit.
Refresh those pages with scripts/cli_reference/record.py at release time and the card shows the
newest recorded log. See docs/social-card.md for the method and the checklist.
"""

import argparse
import html
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = Path(__file__).resolve().parent / "card.html"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
MAX_LINES, MAX_COLS = 20, 64
PRIVATE = ("/home/", "/Users/", "/root/")


def example(page, heading):
    """(command, output lines) of the first recorded run under `### heading` in docs/cli/<page>.md."""
    text = (ROOT / "docs" / "cli" / f"{page}.md").read_text(encoding="utf-8")
    start = text.find(f"### {heading}\n")
    if start < 0:
        raise ValueError(f"docs/cli/{page}.md has no example heading `### {heading}`")
    block = re.search(r"```console\n\$ ((?:sudo )?xref [^\n]+)\n```\n\n(?:\*[^\n]*\*\n\n)?```\w+ output\n(.*?)\n```",
                      text[start:], re.S)
    if not block:
        raise ValueError(f"`### {heading}` in docs/cli/{page}.md has no recorded command with output")
    return block.group(1), block.group(2).split("\n")


def fit(command, lines, keep=None):
    """Lines for the terminal: optionally only those matching `keep`, at most MAX_LINES rows of MAX_COLS."""
    if keep:
        lines = [line for line in lines if re.search(keep, line)]
    shown = lines[: MAX_LINES - 2]
    rows = [("cmd", command)] + [("out", line) for line in shown]
    if len(shown) < len(lines):
        rows.append(("cut", f"… {len(lines) - len(shown)} more lines"))
    return [(kind, line if len(line) <= MAX_COLS else line[: MAX_COLS - 1] + "…") for kind, line in rows]


def terminal_html(rows):
    out = []
    for kind, line in rows:
        if kind == "cmd":
            body = re.sub(r"(\s)(--?[A-Za-z][\w-]*)", r'\1<span class="f">\2</span>', html.escape(line, quote=False))
            out.append(f'<span class="cmd"><span class="p">$</span> {body}</span>')
        else:
            out.append(f'<span class="{kind}">{html.escape(line, quote=False)}</span>')
    return "\n".join(out)


def build_html(spec):
    command, lines = example(spec["page"], spec["example"])
    text = "\n".join([command, *lines])
    leak = next((p for p in PRIVATE if p in text), None)
    if leak:
        raise ValueError(f"the recorded example contains a private path ({leak}); re-record it from a neutral directory")
    rows = fit(command, lines, spec.get("keep"))
    pills = [f'<span class="pill">v{html.escape(spec["version"])}</span>']
    pills += [f'<span class="pill new">{html.escape(p)}</span>' for p in spec.get("new", [])]
    fill = {
        "logo": (ROOT / "docs" / "logo.svg").as_uri(),
        "pills": "".join(pills),
        "headline": html.escape(spec["headline"]),
        "subline": html.escape(spec["subline"]),
        "source": html.escape(f"recorded · docs/cli/{spec['page']}.md"),
        "terminal": terminal_html(rows),
    }
    page = TEMPLATE.read_text(encoding="utf-8")
    for key, value in fill.items():
        page = page.replace("{" + key + "}", value)
    return page


def check_spec(spec):
    for key in ("version", "headline", "subline", "page", "example"):
        if not spec.get(key):
            raise ValueError(f"spec is missing `{key}`")
    if len(spec["headline"]) > 48:
        raise ValueError("headline is longer than 48 characters; it must fit three lines at most")
    if len(spec["subline"]) > 120:
        raise ValueError("subline is longer than 120 characters")
    if len(spec.get("new", [])) > 2:
        raise ValueError("at most two `new` pills")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("spec")
    ap.add_argument("--out", required=True, help="PNG to write (1280x640)")
    ap.add_argument("--html", help="also keep the filled HTML here")
    ap.add_argument("--chrome", default=os.environ.get("CHROME", CHROME))
    args = ap.parse_args()
    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    check_spec(spec)
    page = build_html(spec)
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(args.html) if args.html else Path(tmp) / "card.html"
        source.write_text(page, encoding="utf-8")
        out = Path(args.out).resolve()
        subprocess.run([args.chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
                        "--window-size=1280,640", "--virtual-time-budget=4000", f"--screenshot={out}",
                        source.resolve().as_uri()], check=True, capture_output=True)
    print(f"wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
