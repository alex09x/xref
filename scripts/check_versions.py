#!/usr/bin/env python3
# XRef — check that every published recording and version reference matches the current release
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fail when a page on xrefcode.com or a README still shows output or links of an older xref.

    check_versions.py            report and exit 1 on any stale item

The current version is Cargo.toml's. Each recorded artifact states the xref that produced it; it
must be that version (a development build of it counts), unless PINNED lists the file with the
exact version it is frozen at and why. A pin whose version no longer matches is reported too, so a
frozen record cannot drift silently.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Records deliberately frozen at an older version: path -> (version, reason).
PINNED = {
    "docs/walkthroughs/field-synthetic/environment.txt":
        ("0.4.0", "recording behind the published v0.4.0 field-search article (pinned at 2f01e7b)"),
}


def current_version():
    return re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M).group(1)


def found(path, version, what):
    return {"path": path, "version": version, "what": what}


def recordings():
    """(path, version, what) for every artifact that states which xref produced it."""
    out = []
    data = (ROOT / "docs/recorded-data.js").read_text()
    meta = json.loads(data[data.index("{"):data.rindex("}") + 1])["recording"]
    out.append(found("docs/recorded-data.js", meta["toolVersion"], "home-page recordings (recording.toolVersion)"))
    index = (ROOT / "docs/index.html").read_text()
    for v in re.findall(r"captured with <code>xref ([0-9][^<]*)</code>", index):
        out.append(found("docs/index.html", v, "home-page provenance text"))
    if meta["toolSha256"] not in index:
        out.append(found("docs/index.html", "?", "provenance SHA-256 differs from recorded-data.js toolSha256"))
    walk = json.loads((ROOT / "scripts/live_walkthrough/transcript.json").read_text())["meta"]["xref_version"]
    out.append(found("scripts/live_walkthrough/transcript.json", walk.removeprefix("xref "), "live walkthrough recording"))
    for page in ("docs/live-walkthrough.md", "docs/live-walkthrough.html"):
        if walk not in (ROOT / page).read_text():
            out.append(found(page, "?", f"not rendered from the current transcript ({walk}); run render.py"))
    for page in sorted((ROOT / "docs/cli").glob("*.md")):
        m = re.search(r"Recorded with (?:a development build of xref after |xref )([0-9][\w.\-]*)", page.read_text())
        if m:
            out.append(found(str(page.relative_to(ROOT)), m.group(1), "command reference recording"))
    for env in sorted((ROOT / "docs/walkthroughs").glob("*/environment.txt")):
        m = re.search(r"^xref: xref ([0-9][\w.\-]*)", env.read_text(), re.M)
        if m:
            out.append(found(str(env.relative_to(ROOT)), m.group(1), "walkthrough recording"))
    return out


def links():
    """Install links and the social card that name a release."""
    out = []
    for name in ["docs/index.html", "README.md", *sorted(str(p.relative_to(ROOT)) for p in ROOT.glob("readme/README.*.md"))]:
        text = (ROOT / name).read_text()
        for v in sorted(set(re.findall(r"releases/download/v([0-9][\w.\-]*)/", text))):
            out.append(found(name, v, "release download link"))
    index = (ROOT / "docs/index.html").read_text()
    for v in sorted(set(re.findall(r"og-v([0-9][\w.\-]*)\.png", index))):
        out.append(found("docs/index.html", v, "social preview image (og:image)"))
        if not (ROOT / f"docs/og-v{v}.png").exists():
            out.append(found("docs/index.html", "?", f"og-v{v}.png is referenced but missing"))
    return out


def problems(items, version):
    bad = []
    for item in items:
        pin = PINNED.get(item["path"])
        if item["version"] == "?":
            bad.append(f"{item['path']}: {item['what']}")
        elif pin:
            if item["version"] != pin[0]:
                bad.append(f"{item['path']}: pinned at {pin[0]} ({pin[1]}) but states {item['version']}")
        elif item["version"] != version:
            bad.append(f"{item['path']}: {item['what']} is {item['version']}, current is {version}")
    return bad


def main():
    version = current_version()
    bad = problems(recordings() + links(), version)
    for line in bad:
        print(f"stale: {line}", file=sys.stderr)
    if bad:
        print(f"check_versions: {len(bad)} item(s) do not match xref {version}; re-record or pin them "
              "(see docs/release-automation.md)", file=sys.stderr)
        return 1
    print(f"check_versions: every recording and release link matches xref {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
