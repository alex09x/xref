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
  packaging/homebrew/xref.rb.in .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/update-homebrew.yml \
  docs/index.html docs/404.html docs/_headers docs/logo.svg docs/logo-banner.svg \
  docs/favicon.svg docs/og.png docs/robots.txt docs/sitemap.xml \
  docs/styles.css docs/app.js docs/recorded-data.js
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
PY
git shortlog -sn "${SHORTLOG_REVS[@]}"

echo "==> Checking version synchronization, verbatim README examples, and public hygiene..."
python3 - <<'PY'
import json, re, subprocess, sys

cargo = open("Cargo.toml").read()
m_pkg = re.search(r'^name\s*=\s*"([^"]+)"', cargo, re.M)
m_cargo = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)
assert m_pkg and m_cargo, "name or version not found in Cargo.toml"
pkg_name, ver = m_pkg.group(1), m_cargo.group(1)

lock = open("Cargo.lock").read()
m_lock = re.search(rf'name\s*=\s*"{re.escape(pkg_name)}"\nversion\s*=\s*"([^"]+)"', lock)
assert m_lock, f"{pkg_name} package entry not found in Cargo.lock"
if m_lock.group(1) != ver:
    sys.exit(f"ERROR: Cargo.lock {pkg_name} version ({m_lock.group(1)}) != Cargo.toml ({ver})")

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

for m_sc in re.finditer(r"<script\b([^>]*)>(.*?)</script>", idx, re.I | re.S):
    attrs, body = m_sc.group(1), m_sc.group(2).strip()
    if re.search(r'\bsrc\s*=', attrs, re.I):
        continue
    if re.search(r'\btype\s*=\s*["\']application/ld\+json["\']', attrs, re.I):
        ld = json.loads(body)
        if ld.get("@type") != "SoftwareApplication" or ld.get("softwareVersion") != ver:
            sys.exit(f"ERROR: JSON-LD SoftwareApplication softwareVersion mismatch in docs/index.html (expected {ver})")
        continue
    sys.exit("ERROR: executable inline <script> found in docs/index.html (violates strict CSP)")
if re.search(r'\sstyle\s*=', idx, re.I):
    sys.exit("ERROR: inline style= attribute found in docs/index.html (violates strict CSP)")

CONCEPT_DOI = "10.5281/zenodo.23878789"
for doc_path, content in [("CITATION.cff", cit), ("README.md", readme), ("docs/index.html", idx)]:
    if CONCEPT_DOI not in content:
        sys.exit(f"ERROR: concept DOI {CONCEPT_DOI} missing from {doc_path}")

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

echo "==> Checking localized README examples and links..."
python3 scripts/check-readme-translations.py
python3 scripts/test-readme-translations.py

echo "==> Checking the Live Analysis walkthrough recorder (unprivileged fake observers)..."
python3 scripts/live_walkthrough/test_record.py

echo "==> Checking the generated /docs/ site pages against docs/*.md..."
python3 scripts/site_docs/test_md.py
python3 scripts/site_docs/build.py --check
