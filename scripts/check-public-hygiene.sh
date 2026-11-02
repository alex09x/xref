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

echo "==> Checking .mailmap collapses git shortlog to a single identity..."
identities="$(git shortlog -sne HEAD | wc -l | tr -d ' ')"
git shortlog -sne HEAD
if [[ "$identities" -ne 1 ]]; then
  echo "ERROR: expected 1 canonical author identity in git shortlog, got $identities" >&2
  exit 1
fi

echo "==> Checking version synchronization across Cargo.toml, CITATION.cff, README.md, and docs/index.html..."
python3 - <<'PY'
import re, sys

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

forbidden = re.compile(
    r"(192\.168\.[0-9.]+|/Users/(?!dev\b|user\b)[A-Za-z0-9_-]+|/home/(?!dev\b|user\b)[A-Za-z0-9_-]+|KYB\x3a)",
    re.I,
)
import subprocess
tracked = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
for path in tracked:
    if path.endswith(".png"):
        continue
    text = open(path, errors="replace").read()
    m = forbidden.search(text)
    if m:
        sys.exit(f"ERROR: private marker '{m.group(0)}' found in tracked file {path}")

print(f"OK: version v{ver} synchronized and tracked files clean.")
PY
