#!/usr/bin/env bash
# XRef — reproduce the xref field walkthrough on the synthetic test program
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Usage (Linux x86-64, from a checkout of tag v0.4.0):
#   bash docs/walkthroughs/field-synthetic/capture.sh OUT_DIR
# Downloads the published xref 0.4.0 Linux archive, generates and compiles the synthetic
# test program, then runs every walkthrough command with an empty cache. OUT_DIR receives
# environment.txt (identities) and transcript.txt (commands, stdout, stderr, exit codes).
set -euo pipefail

OUT=$(mkdir -p "$1" && cd "$1" && pwd)
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
TAG=v0.4.0
ARCHIVE=xref-$TAG-x86_64-unknown-linux-gnu.tar.gz
ARCHIVE_SHA256=15a32d4bbe59307709c058e6c6379d98814fcafe106d8edc0379165454edf0a2
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

curl -fsSLO "https://github.com/alex09x/xref/releases/download/$TAG/$ARCHIVE"
echo "$ARCHIVE_SHA256  $ARCHIVE" | sha256sum -c - >/dev/null
tar -xzf "$ARCHIVE" xref
export PATH="$WORK:$PATH"
XREF=xref

python3 "$REPO/tests/fixtures/field_perf/generate.py" program --functions 2000 --writers
CFLAGS="-O2 -g0 -fno-inline -fno-ipa-icf"
cc $CFLAGS program/target.c program/bulk.S -o program/target
objcopy --strip-all program/target program/target-stripped
cp program/target.c "$OUT/target.c"

{
  echo "utc: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "xref: $("$XREF" --version); archive $ARCHIVE sha256 $ARCHIVE_SHA256; binary sha256 $(sha256sum "$WORK/xref" | cut -d' ' -f1)"
  echo "xref build_revision: $("$XREF" -b program/target-stripped query '{"operation":"info"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["build_revision"])')"
  echo "generator: tests/fixtures/field_perf/generate.py sha256 $(sha256sum "$REPO/tests/fixtures/field_perf/generate.py" | cut -d' ' -f1); args: --functions 2000 --writers"
  echo "compiler: $(cc --version | head -1); flags: $CFLAGS"
  echo "strip: $(objcopy --version | head -1); objcopy --strip-all"
  echo "os: $(uname -srm); cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "target.c sha256: $(sha256sum program/target.c | cut -d' ' -f1)"
  echo "target (unstripped) sha256: $(sha256sum program/target | cut -d' ' -f1)"
  echo "target-stripped sha256: $(sha256sum program/target-stripped | cut -d' ' -f1)"
  echo "symbols (unstripped build, for checking the answer):"
  nm program/target | grep -E ' (serializer|writer|emit|main)$' | sed 's/^/  /'
} > "$OUT/environment.txt"

# No result replay and no background daemon in any run. Every "cold" run gets its own empty
# cache directory; the one "index reuse" run uses the cache the previous cold run built.
export XREF_NO_RESULT_CACHE=1 XREF_NO_DAEMON=1
run() {
  local code=0
  echo "\$ $*"
  echo "# cache: $CACHE_NOTE"
  "$@" > "$WORK/stdout" 2> "$WORK/stderr" || code=$?
  echo "--- stdout"; cat "$WORK/stdout"
  echo "--- stderr"; cat "$WORK/stderr"
  echo "--- exit $code"; echo
}
cold() { export XDG_CACHE_HOME; XDG_CACHE_HOME=$(mktemp -d "$WORK/cache.XXXX"); CACHE_NOTE="cold (new empty cache)"; run "$@"; }
reuse() { CACHE_NOTE="index reuse (cache built by the previous cold run)"; run "$@"; }
cd program
X="xref -b target-stripped"
{
  cold $X stats
  cold $X field --keys c,m,e --layout-only
  cold $X field --keys c,m,e --write --writes-all-of m,e --limit 5
  reuse $X field --keys c,m,e --write --writes-all-of m,e --writer-root argument --limit 3 --json
  cold $X field --keys c,m,e --write --writes-all-of m,e --limit 1 --json
} > "$OUT/transcript.txt"
SER=$(nm target | awk '$3=="serializer"{print "0x"$1}' | sed 's/0x0*/0x/')
WRI=$(nm target | awk '$3=="writer"{print "0x"$1}' | sed 's/0x0*/0x/')
{
  cold $X asm "$SER"
  cold $X asm "$WRI"
  cold $X c "$WRI"
  cold $X callers "$WRI"
} >> "$OUT/transcript.txt"
echo "wrote $OUT/environment.txt and $OUT/transcript.txt"
