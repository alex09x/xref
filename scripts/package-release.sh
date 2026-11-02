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

VER="$(python3 -c 'import re; print(re.search(r"^version\s*=\s*\"([^\"]+)\"", open("Cargo.toml").read(), re.M).group(1))')"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
SYSROOT_DIR="$(rustc --print sysroot)"

REMAP_FLAGS=(
  "--remap-path-prefix=${ROOT}=."
  "--remap-path-prefix=${CARGO_HOME_DIR}=/cargo"
  "--remap-path-prefix=${SYSROOT_DIR}=/rustc"
  "--remap-path-prefix=${HOME}=/build"
)

echo "==> Building clean remapped release binary xref v${VER}..."
CARGO_INCREMENTAL=0 RUSTFLAGS="${REMAP_FLAGS[*]}" cargo build --release --locked

BIN="target/release/xref"
"$BIN" --version

echo "==> Auditing binary strings for leaked host/home build paths..."
python3 - "$BIN" <<'PY'
import re, sys

data = open(sys.argv[1], "rb").read()
for pat in [b"/home/", b"/Users/"]:
    cnt = data.count(pat)
    if cnt > 0:
        sys.exit(f"ERROR: binary contains {cnt} occurrence(s) of {pat.decode()}")
print("OK: 0 leaked build paths in release ELF.")
PY

if command -v readelf >/dev/null 2>&1; then
  MAX_GLIBC="$(readelf -V "$BIN" | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -n 1 || true)"
  echo "==> Maximum required GLIBC symbol version: ${MAX_GLIBC:-unknown}"
fi

OUT_DIR="${1:-dist}"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR/stage"

cp "$BIN" "$OUT_DIR/stage/xref"
chmod 755 "$OUT_DIR/stage/xref"
cp README.md LICENSE-MIT LICENSE-APACHE CITATION.cff "$OUT_DIR/stage/"

ARCHIVE="xref-v${VER}-x86_64-unknown-linux-gnu.tar.gz"
if tar --version 2>/dev/null | grep -qi 'gnu'; then
  tar --owner=0 --group=0 --numeric-owner -C "$OUT_DIR/stage" -czf "$OUT_DIR/$ARCHIVE" xref README.md LICENSE-MIT LICENSE-APACHE CITATION.cff
else
  COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --uname root --gname root -C "$OUT_DIR/stage" -czf "$OUT_DIR/$ARCHIVE" xref README.md LICENSE-MIT LICENSE-APACHE CITATION.cff
fi
rm -rf "$OUT_DIR/stage"

(
  cd "$OUT_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$ARCHIVE" > SHA256SUMS
  else
    shasum -a 256 "$ARCHIVE" > SHA256SUMS
  fi
  cat SHA256SUMS
)
