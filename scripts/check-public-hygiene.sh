#!/usr/bin/env bash
#
# xref — Ultra blazing fast cross-references of an x86-64 ELF binary
# Copyright (c) 2026 Alexander Panasenko
#
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Checking required public files..."
for f in \
  Cargo.toml LICENSE-MIT LICENSE-APACHE CITATION.cff README.md .mailmap \
  docs/index.html docs/404.html docs/_headers docs/favicon.svg docs/og.png \
  docs/robots.txt docs/sitemap.xml docs/styles.css docs/app.js docs/recorded-data.js
do
  if [[ ! -s "$f" ]]; then
    echo "ERROR: missing or empty required file: $f" >&2
    exit 1
  fi
done

echo "==> Checking .mailmap canonicalizes owner commit identities (allowing external contributors)..."
# On GitHub pull_request events, HEAD is an ephemeral synthetic merge commit
# created by GitHub using the account's primary web email; inspect HEAD^1 and HEAD^2 directly.
if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]] && git rev-parse --verify HEAD^2 >/dev/null 2>&1; then
  SHORTLOG_REVS=("HEAD^1" "HEAD^2")
else
  SHORTLOG_REVS=("HEAD")
fi
python3 - "${SHORTLOG_REVS[@]}" <<'PY'
import re, subprocess, sys

out = subprocess.check_output(["git", "shortlog", "-sne", *sys.argv[1:]], text=True)
for raw in out.splitlines():
    m = re.match(r"^\s*\d+\s+(.+?)\s+<([^>]+)>\s*$", raw)
    if not m:
        sys.exit("ERROR: unexpected git shortlog line format")
    name, email = m.group(1).strip(), m.group(2).strip().lower()
    if email == "alex@prod.codes" and name != "Alexander Panasenko":
        sys.exit(f"ERROR: unmapped owner name '{name}' for canonical owner email; update .mailmap")
    if ("panasenko" in name.lower() or name.lower() == "alex") and email != "alex@prod.codes":
        sys.exit(f"ERROR: owner commit under '{name}' uses non-canonical email domain; commit with alex@prod.codes or map in .mailmap")
PY
git shortlog -sn "${SHORTLOG_REVS[@]}"

echo "==> Checking version synchronization, verbatim README examples, and public hygiene..."
python3 - <<'PY'
import json, re, subprocess, sys

cargo = open("Cargo.toml").read()
m_cargo = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)
assert m_cargo, "version not found in Cargo.toml"
ver = m_cargo.group(1)

cit = open("CITATION.cff").read()
m_cit = re.search(r'^version:\s*([^\s]+)', cit, re.M)
assert m_cit, "version not found in CITATION.cff"
if m_cit.group(1).strip('"\'') != ver:
    sys.exit(f"ERROR: CITATION.cff version ({m_cit.group(1)}) != Cargo.toml ({ver})")

idx = open("docs/index.html").read()
if f"xref v{ver}" not in idx or f"v{ver}/xref-v{ver}-x86_64-unknown-linux-gnu.tar.gz" not in idx:
    sys.exit(f"ERROR: docs/index.html does not match version {ver}")

readme = open("README.md").read()
if f"v{ver}/xref-v{ver}-x86_64-unknown-linux-gnu.tar.gz" not in readme or f"--tag v{ver}" not in readme:
    sys.exit(f"ERROR: README.md install commands do not match version {ver}")

if re.search(r"<script(?![^>]*\bsrc=)", idx, re.I):
    sys.exit("ERROR: inline <script> found in docs/index.html (violates strict CSP)")

rec_txt = open("docs/recorded-data.js").read()
rec = json.loads(rec_txt[rec_txt.index("{") : rec_txt.rindex("}") + 1])
recorded_by_cmd = {}
for g in rec.get("scenarioGroups", []):
    for it in g.get("items", []):
        for v in it.get("variants", []):
            recorded_by_cmd[v["cmd"]] = v["stdout"].rstrip("\n")
for fn in rec.get("functions", []):
    for view_list in fn.get("views", {}).values():
        for v in view_list:
            recorded_by_cmd[v["cmd"]] = v["stdout"].rstrip("\n")

examples_sec = readme.split("## Recorded Examples", 1)[1].split("\n## ", 1)[0]
blocks = re.findall(r"```[a-z]*\n\$ (xref -b xref\.stripped [^\n]+)\n(.*?)\n```", examples_sec, re.S)
if len(blocks) < 4:
    sys.exit(f"ERROR: expected >= 4 recorded example blocks in README.md, found {len(blocks)}")
for cmd, body in blocks:
    if cmd not in recorded_by_cmd:
        sys.exit(f"ERROR: README example command '{cmd}' not found in docs/recorded-data.js")
    norm_body = [ln.rstrip() for ln in body.splitlines()]
    norm_rec = [ln.rstrip() for ln in recorded_by_cmd[cmd].splitlines()]
    if norm_body != norm_rec:
        sys.exit(f"ERROR: README example output for '{cmd}' does not match verbatim docs/recorded-data.js stdout")

forbidden = re.compile(
    r"(192\.168\.[0-9.]+|/Users/(?!dev\b|user\b)[A-Za-z0-9_-]+|/home/(?!dev\b|user\b)[A-Za-z0-9_-]+|KYB\x3a)",
    re.I,
)
tracked = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
for path in tracked:
    if path.endswith(".png"):
        continue
    text = open(path, errors="replace").read()
    m = forbidden.search(text)
    if m:
        sys.exit(f"ERROR: private marker '{m.group(0)}' found in tracked file {path}")

print(f"OK: version v{ver} synchronized, {len(blocks)} README examples verified verbatim, and tracked files clean.")
PY
