#!/usr/bin/env python3
# XRef — render docs/*.md into the xrefcode.com /docs/ section
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the Markdown guides in docs/ into static pages under docs/docs/ (served at /docs/).

    build.py            write the pages
    build.py --check    exit 1 when a committed page differs from what the Markdown renders to

The Markdown files stay the single source; the HTML is generated and must not be edited by hand.
"""

import argparse
import sys
from pathlib import Path

import md
from md import render, title_and_summary
from pages import GROUPS, page_html, index_html

md.SITE_PAGES.update(name for _, names in GROUPS for name in names)

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
OUT = DOCS / "docs"


def outputs():
    """Map each output path to its rendered text."""
    pages = {}
    meta = []
    for group, names in GROUPS:
        for name in names:
            source = (DOCS / f"{name}.md").read_text(encoding="utf-8")
            title, summary = title_and_summary(source)
            body, toc = render(source, name)
            meta.append((group, name, title, summary))
            pages[name] = (title, summary, body, toc)
    result = {}
    for name, (title, summary, body, toc) in pages.items():
        result[OUT / f"{name}.html"] = page_html(name, title, summary, body, toc, meta)
    result[OUT / "index.html"] = index_html(meta)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify committed pages instead of writing them")
    args = parser.parse_args()
    stale = []
    for path, text in outputs().items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(path.relative_to(ROOT))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if args.check:
        expected = set(outputs())
        extra = [p.relative_to(ROOT) for p in OUT.glob("*.html") if p not in expected]
        for path in stale + extra:
            print(f"stale or unexpected site docs page: {path} (run scripts/site_docs/build.py)", file=sys.stderr)
        return 1 if stale or extra else 0
    print(f"wrote {len(outputs())} pages to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
