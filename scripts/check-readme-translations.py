#!/usr/bin/env python3
# XRef Code — README translation checks
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Check translated READMEs without changing files or accessing the network."""

import argparse
from collections import Counter
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
LOCALES = ("ru", "zh-CN", "es", "pt-BR", "ja", "de", "fr", "ko", "ar")
REPO = "https://github.com/alex09x/xref/blob/main/"
FENCES = re.compile(r"^```[^\n]*\n.*?^```[ \t]*$", re.MULTILINE | re.DOTALL)


def headings(text):
    return re.findall(r"^## (.+)$", text, re.MULTILINE)


def inline_commands(text):
    prose = FENCES.sub("", text)
    return Counter(re.findall(r"`((?:xref|cargo|brew)\s+[^`]+)`", prose))


def check(path, canonical):
    text = path.read_text(encoding="utf-8")
    errors = []
    if FENCES.findall(text) != FENCES.findall(canonical):
        errors.append("fenced code, CLI output, diagrams or BibTeX differ from English")
    if len(headings(text)) != len(headings(canonical)):
        errors.append("top-level sections differ from English")
    if inline_commands(text) != inline_commands(canonical):
        errors.append("inline CLI commands or benchmark commands differ from English")
    if not re.search(r"<!-- translation-source: [0-9a-f]{40} -->", text):
        errors.append("missing English source commit marker")
    if path.name == "README.ar.md" and ('dir="rtl"' not in text or 'dir="ltr"' not in text):
        errors.append("Arabic needs RTL prose and LTR code regions")
    for target in ("README.md", *(f"readme/README.{loc}.md" for loc in LOCALES)):
        if REPO + target not in text:
            errors.append("language selector missing " + target)

    prose = FENCES.sub("", text)
    targets = re.findall(r"\]\(([^\s)]+)\)", prose)
    targets += re.findall(r"\b(?:href|src)=[\"']([^\"']+)[\"']", prose)
    anchors = set(re.findall(r"<a\s+(?:name|id)=[\"']([^\"']+)[\"']", prose))
    for target in targets:
        parts = urlsplit(target)
        if parts.scheme or parts.netloc:
            continue
        if parts.path:
            local = (path.parent / unquote(parts.path)).resolve()
            if not local.is_relative_to(ROOT) or not local.exists():
                errors.append("broken local link/image: " + target)
        elif parts.fragment and unquote(parts.fragment) not in anchors:
            errors.append("missing explicit navigation anchor: " + parts.fragment)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="specific translated files; default: all nine")
    parser.add_argument("--source-only", action="store_true", help="inspect the English input only")
    args = parser.parse_args()
    canonical = (ROOT / "README.md").read_text(encoding="utf-8")
    if not FENCES.findall(canonical) or not headings(canonical):
        parser.error("English README has no fenced examples or sections")
    if args.source_only:
        print(f"English source: {len(headings(canonical))} sections, {len(FENCES.findall(canonical))} fenced blocks")
        return 0

    paths = [Path(p).resolve() for p in args.paths] if args.paths else [
        ROOT / "readme" / f"README.{loc}.md" for loc in LOCALES
    ]
    failed = False
    for path in paths:
        try:
            errors = check(path, canonical)
        except (OSError, UnicodeError) as error:
            errors = [str(error)]
        for error in errors:
            print(f"{path.name}: {error}", file=sys.stderr)
        failed |= bool(errors)
    if not failed:
        print(f"Verified {len(paths)} translations: verbatim code blocks, sections and local links")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
