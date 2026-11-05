#!/usr/bin/env python3
# XRef — public release channel verification
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Fail closed if a public release channel has not converged to this version."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.request import Request, urlopen

from github_release import archive_names, identity


def fetch(url):
    request = Request(url, headers={"User-Agent": "XRef-release-verification/1.0"})
    with urlopen(request, timeout=20) as response:
        return response.read(), response.headers


def check_site(tag):
    raw, headers = fetch("https://xrefcode.com/")
    html = raw.decode()
    if not re.search(r'"softwareVersion"\s*:\s*"' + re.escape(tag[1:]) + '"', html):
        raise ValueError("site SoftwareApplication version has not updated")
    if f"{tag}/xref-{tag}-x86_64-unknown-linux-gnu.tar.gz" not in html:
        raise ValueError("site install URL has not updated")
    if not headers.get("Content-Security-Policy") or not headers.get("Strict-Transport-Security"):
        raise ValueError("site CSP or HSTS is missing")
    # The active card is whatever og:image names; it must be og-vX.Y.Z.png or og-vX.Y.Z-<variant>.png
    # for this release (a variant lets a new card for the same version get a fresh, uncached URL).
    active = re.search(r'<meta property="og:image" content="https://xrefcode\.com/(og-[^"/]+\.png)"', html)
    pattern = r"og-" + re.escape(tag) + r"(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?\.png"  # same names as check_versions.py
    if not active or not re.fullmatch(pattern, active.group(1)):
        raise ValueError("site social card does not reference this version")
    image_path = active.group(1)
    image, _ = fetch(f"https://xrefcode.com/{image_path}")
    expected = hashlib.sha256((Path("docs") / image_path).read_bytes()).hexdigest()
    if hashlib.sha256(image).hexdigest() != expected:
        raise ValueError("deployed social image differs from the tagged image")
    return {"channel": "site", "tag": tag, "url": "https://xrefcode.com/", "og_sha256": expected}


def check_homebrew(tag):
    manifest_raw, _ = fetch(f"https://github.com/alex09x/xref/releases/download/{tag}/release-manifest.json")
    manifest = json.loads(manifest_raw)
    if manifest.get("tag") != tag or manifest.get("version") != tag[1:]:
        raise ValueError("release manifest version mismatch")
    formula_raw, _ = fetch("https://raw.githubusercontent.com/alex09x/homebrew-apps/main/Formula/xref.rb")
    formula = formula_raw.decode()
    if not re.search(r'\bversion\s+"' + re.escape(tag[1:]) + '"', formula):
        raise ValueError("Homebrew main formula has not updated")
    entries = manifest.get("archives", [])
    if len(entries) != 2 or {f["name"] for f in entries} != set(archive_names(tag)):
        raise ValueError("release manifest archive set mismatch")
    for entry in entries:
        url = f"https://github.com/alex09x/xref/releases/download/{tag}/{entry['name']}"
        # Match each URL to its own checksum instead of accepting hashes elsewhere.
        pattern = r'url\s+"' + re.escape(url) + r'"\s+sha256\s+"' + re.escape(entry["sha256"]) + '"'
        if not re.search(pattern, formula):
            raise ValueError(f"Homebrew URL/hash mismatch for {entry['name']}")
    return {"channel": "homebrew", "tag": tag, "formula_sha256": hashlib.sha256(formula_raw).hexdigest()}


def wait_for(check, tag, seconds):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return check(tag)
        except (OSError, ValueError, KeyError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"channel verification incomplete: {error}") from error
            time.sleep(min(10, max(0, deadline - time.monotonic())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("channel", choices=["site", "homebrew"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    identity(args.tag, "0" * 40)
    if not 0 <= args.wait_seconds <= 1800:
        parser.error("wait budget must be in 0..1800 seconds")
    try:
        check = check_site if args.channel == "site" else check_homebrew
        receipt = wait_for(check, args.tag, args.wait_seconds)
        payload = json.dumps(receipt, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload)
        print(payload, end="")
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
