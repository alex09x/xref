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
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"

OUT_DIR="${1:-dist}"
TARGET="${2:-$HOST_TARGET}"

case "$TARGET" in
  x86_64-unknown-linux-gnu|aarch64-apple-darwin) ;;
  *)
    echo "ERROR: unsupported release target '$TARGET' (expected x86_64-unknown-linux-gnu or aarch64-apple-darwin)" >&2
    exit 1
    ;;
esac

REMAP_FLAGS=(
  "--remap-path-prefix=${ROOT}=."
  "--remap-path-prefix=${CARGO_HOME_DIR}=/cargo"
  "--remap-path-prefix=${SYSROOT_DIR}=/rustc"
  "--remap-path-prefix=${HOME}=/build"
)

echo "==> Building clean remapped release binary xref v${VER} (${TARGET})..."
CARGO_INCREMENTAL=0 RUSTFLAGS="${REMAP_FLAGS[*]}" cargo build --release --locked --target "$TARGET"

BIN="target/${TARGET}/release/xref"
if [[ "$TARGET" == "$HOST_TARGET" ]]; then
  "$BIN" --version
fi

echo "==> Auditing binary target format and leaked host/home build paths..."
python3 - "$BIN" "$TARGET" <<'PY'
import re, sys

data = open(sys.argv[1], "rb").read()
target = sys.argv[2]

if target == "x86_64-unknown-linux-gnu":
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        sys.exit("ERROR: built binary is not 64-bit little-endian ELF")
    e_machine = int.from_bytes(data[18:20], "little")
    if e_machine != 0x3E:
        sys.exit(f"ERROR: built ELF e_machine=0x{e_machine:x}, expected 0x3e (EM_X86_64)")
elif target == "aarch64-apple-darwin":
    if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
        sys.exit("ERROR: built binary is not 64-bit Mach-O (MH_MAGIC_64)")
    cputype = int.from_bytes(data[4:8], "little")
    if cputype != 0x0100000C:
        sys.exit(f"ERROR: built Mach-O cputype=0x{cputype:x}, expected 0x0100000c (CPU_TYPE_ARM64)")

leaks = re.findall(rb"/(?:home|Users)/[A-Za-z0-9_.-]{2,}/", data)
if leaks:
    sample = sorted({m.decode("ascii", "replace") for m in leaks})[:5]
    sys.exit(f"ERROR: binary contains {len(leaks)} leaked host path(s): {sample}")
print(f"OK: verified {target} binary with 0 leaked build paths.")
PY

if [[ "$TARGET" == "x86_64-unknown-linux-gnu" ]] && command -v readelf >/dev/null 2>&1; then
  MAX_GLIBC="$(readelf -V "$BIN" | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -n 1 || true)"
  echo "==> Maximum required GLIBC symbol version: ${MAX_GLIBC:-unknown}"
fi

mkdir -p "$OUT_DIR"
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xref-pkg.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT
mkdir -p "$STAGE_DIR/bundle"

cp "$BIN" "$STAGE_DIR/bundle/xref"
chmod 755 "$STAGE_DIR/bundle/xref"
if [[ "$TARGET" == "aarch64-apple-darwin" ]] && command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - "$STAGE_DIR/bundle/xref"
fi
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
    sha256sum "$ARCHIVE" > "${ARCHIVE}.sha256"
  else
    shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256"
  fi
)

mv -f "$STAGE_DIR/$ARCHIVE" "$OUT_DIR/$ARCHIVE"
mv -f "$STAGE_DIR/${ARCHIVE}.sha256" "$OUT_DIR/${ARCHIVE}.sha256"

(
  cd "$OUT_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum xref-v"${VER}"-*.tar.gz | sort -k2 > SHA256SUMS
  else
    shasum -a 256 xref-v"${VER}"-*.tar.gz | sort -k2 > SHA256SUMS
  fi
  cat "${ARCHIVE}.sha256"
)
