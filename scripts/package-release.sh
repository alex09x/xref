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

TARGET="x86_64-unknown-linux-gnu"
echo "==> Building clean remapped release binary xref v${VER} (${TARGET})..."
CARGO_INCREMENTAL=0 RUSTFLAGS="${REMAP_FLAGS[*]}" cargo build --release --locked --target "$TARGET"

BIN="target/${TARGET}/release/xref"
if [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]]; then
  "$BIN" --version
fi

echo "==> Auditing ELF target architecture and leaked host/home build paths..."
python3 - "$BIN" <<'PY'
import sys

data = open(sys.argv[1], "rb").read()
if len(data) < 20 or data[:4] != b"\x7fELF":
    sys.exit("ERROR: built binary is not an ELF image")
if data[4] != 2 or data[5] != 1:
    sys.exit("ERROR: built ELF is not 64-bit little-endian (ELFCLASS64/ELFDATA2LSB)")
e_machine = int.from_bytes(data[18:20], "little")
if e_machine != 0x3E:
    sys.exit(f"ERROR: built ELF e_machine=0x{e_machine:x}, expected 0x3e (EM_X86_64)")

for pat in [b"/home/", b"/Users/"]:
    cnt = data.count(pat)
    if cnt > 0:
        sys.exit(f"ERROR: binary contains {cnt} occurrence(s) of {pat.decode()}")
print("OK: verified ELF64 EM_X86_64 with 0 leaked build paths.")
PY

if command -v readelf >/dev/null 2>&1; then
  MAX_GLIBC="$(readelf -V "$BIN" | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -n 1 || true)"
  echo "==> Maximum required GLIBC symbol version: ${MAX_GLIBC:-unknown}"
fi

OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xref-pkg.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT
mkdir -p "$STAGE_DIR/bundle"

cp "$BIN" "$STAGE_DIR/bundle/xref"
chmod 755 "$STAGE_DIR/bundle/xref"
cp README.md LICENSE-MIT LICENSE-APACHE CITATION.cff "$STAGE_DIR/bundle/"
chmod 644 "$STAGE_DIR/bundle/README.md" "$STAGE_DIR/bundle/LICENSE-MIT" "$STAGE_DIR/bundle/LICENSE-APACHE" "$STAGE_DIR/bundle/CITATION.cff"

ARCHIVE="xref-v${VER}-${TARGET}.tar.gz"
if tar --version 2>/dev/null | grep -qi 'gnu'; then
  tar --owner=0 --group=0 --numeric-owner -C "$STAGE_DIR/bundle" -czf "$STAGE_DIR/$ARCHIVE" xref README.md LICENSE-MIT LICENSE-APACHE CITATION.cff
else
  COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --uname root --gname root -C "$STAGE_DIR/bundle" -czf "$STAGE_DIR/$ARCHIVE" xref README.md LICENSE-MIT LICENSE-APACHE CITATION.cff
fi

(
  cd "$STAGE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$ARCHIVE" > SHA256SUMS
  else
    shasum -a 256 "$ARCHIVE" > SHA256SUMS
  fi
)

mv -f "$STAGE_DIR/$ARCHIVE" "$OUT_DIR/$ARCHIVE"
mv -f "$STAGE_DIR/SHA256SUMS" "$OUT_DIR/SHA256SUMS"
cat "$OUT_DIR/SHA256SUMS"
