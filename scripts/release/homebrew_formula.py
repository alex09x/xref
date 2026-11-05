# XRef — render the Homebrew formula from a published release manifest
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render Formula/xref.rb for a release and refuse to replace a newer tap formula.

    homebrew_formula.py render --tag vX.Y.Z --manifest M --template T --tap-formula F

Writes the rendered formula to F and exits 0, or leaves F unchanged and exits 0
when F already holds a newer version (a re-run of an older release must not roll
the tap back). Malformed input exits non-zero.
"""

import argparse
import json
import re
import sys
from pathlib import Path

TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION = re.compile(r'^\s*version\s+"(\d+)\.(\d+)\.(\d+)"', re.MULTILINE)
BASE = "https://github.com/alex09x/xref/releases/download/"


def parse_tag(tag):
    match = TAG.match(tag)
    if not match:
        raise ValueError(f"invalid release tag {tag!r}")
    return tuple(int(part) for part in match.groups())


def formula_version(text):
    match = VERSION.search(text)
    return tuple(int(part) for part in match.groups()) if match else None


def render(tag, manifest, template):
    parse_tag(tag)
    if manifest.get("tag") != tag or manifest.get("version") != tag[1:]:
        raise ValueError("release manifest version mismatch")
    sha = {entry["name"]: entry["sha256"] for entry in manifest.get("archives", [])}
    mac = f"xref-{tag}-aarch64-apple-darwin.tar.gz"
    linux = f"xref-{tag}-x86_64-unknown-linux-gnu.tar.gz"
    if mac not in sha or linux not in sha:
        raise ValueError("release manifest lacks a platform archive")
    values = {
        "@@XREF_VERSION@@": tag[1:],
        "@@XREF_MACOS_ARM64_URL@@": f"{BASE}{tag}/{mac}",
        "@@XREF_MACOS_ARM64_SHA256@@": sha[mac],
        "@@XREF_LINUX_X86_64_URL@@": f"{BASE}{tag}/{linux}",
        "@@XREF_LINUX_X86_64_SHA256@@": sha[linux],
    }
    for key, value in values.items():
        template = template.replace(key, value)
    if "@@" in template:
        raise ValueError("unrendered placeholder in formula template")
    return template


def update(tag, manifest, template, current):
    """Return the formula text to write, or None when `current` is newer than `tag`."""
    existing = formula_version(current) if current else None
    if existing is not None and existing > parse_tag(tag):
        return None
    return render(tag, manifest, template)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("render")
    cmd.add_argument("--tag", required=True)
    cmd.add_argument("--manifest", required=True, type=Path)
    cmd.add_argument("--template", required=True, type=Path)
    cmd.add_argument("--tap-formula", required=True, type=Path)
    args = parser.parse_args()
    current = args.tap_formula.read_text(encoding="utf-8") if args.tap_formula.exists() else None
    text = update(
        args.tag,
        json.loads(args.manifest.read_text(encoding="utf-8")),
        args.template.read_text(encoding="utf-8"),
        current,
    )
    if text is None:
        print(f"Tap formula is newer than {args.tag}; leaving it unchanged", file=sys.stderr)
        return 0
    args.tap_formula.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
