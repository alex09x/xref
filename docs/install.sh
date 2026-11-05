#!/bin/sh
# XRef — installer: curl -fsSL https://xrefcode.com/install.sh | sh
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Picks the install method itself:
#   1. a prebuilt release binary (Linux x86-64 with glibc >= 2.34, macOS Apple Silicon),
#      downloaded from GitHub Releases and checked against its published SHA-256;
#   2. otherwise `cargo install xref-code --locked`, when cargo is available;
#   3. otherwise it stops and lists the options.
#
# Settings (environment variables):
#   XREF_VERSION      release tag to install, e.g. v0.4.0 (default: the latest release)
#   XREF_INSTALL_DIR  where to put the binary (default: /usr/local/bin if writable, else ~/.local/bin)
#   XREF_METHOD       auto (default), binary or cargo
#
# Everything runs inside main(), so a download cut short never executes a partial script.

set -eu

REPO="alex09x/xref"

say() { printf 'xref-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

fetch() { # URL FILE
    if have curl; then curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2" || die "download failed: $1"
    elif have wget; then wget -q --https-only -O "$2" "$1" || die "download failed: $1"
    else die "need curl or wget"; fi
}

latest_tag() {
    url="https://github.com/$REPO/releases/latest"
    if have curl; then loc=$(curl --proto '=https' -fsSI "$url" | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | tail -n 1)
    else loc=$(wget -q --https-only --max-redirect=0 -S -O /dev/null "$url" 2>&1 | awk 'tolower($1)=="location:" {print $2}' | tail -n 1); fi
    printf '%s\n' "${loc##*/}"
}

sha256_of() { # FILE
    if have sha256sum; then sha256sum "$1" | awk '{print $1}'
    elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
    else die "need sha256sum or shasum to verify the download"; fi
}

glibc_ok() { # glibc >= 2.34 (the release binary's newest symbol version)
    have ldd || return 1
    v=$(ldd --version 2>&1 | head -n 1 | grep -o '[0-9][0-9]*\.[0-9][0-9]*$' || true)
    [ -n "$v" ] || return 1
    major=${v%%.*}; minor=${v#*.}
    [ "$major" -gt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -ge 34 ]; }
}

target() { # prints the release target triple, or nothing when no prebuilt binary fits
    os=$(uname -s); arch=$(uname -m)
    case "$os/$arch" in
        Linux/x86_64) glibc_ok && echo x86_64-unknown-linux-gnu || true ;;
        Darwin/arm64) echo aarch64-apple-darwin ;;
        Darwin/x86_64) # Rosetta shell on Apple Silicon still runs arm64 binaries natively
            [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ] && echo aarch64-apple-darwin || true ;;
    esac
}

install_dir() {
    if [ -n "${XREF_INSTALL_DIR:-}" ]; then echo "$XREF_INSTALL_DIR"
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then echo /usr/local/bin
    else echo "$HOME/.local/bin"; fi
}

install_binary() { # TARGET
    tag=${XREF_VERSION:-$(latest_tag)}
    case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) die "could not determine the release tag (got '$tag'); set XREF_VERSION=vX.Y.Z" ;; esac
    name="xref-$tag-$1.tar.gz"
    base="https://github.com/$REPO/releases/download/$tag"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT INT TERM
    say "downloading $name"
    fetch "$base/$name" "$tmp/$name"
    fetch "$base/$name.sha256" "$tmp/$name.sha256"
    want=$(awk '{print $1}' "$tmp/$name.sha256")
    got=$(sha256_of "$tmp/$name")
    [ -n "$want" ] && [ "$want" = "$got" ] || die "SHA-256 mismatch for $name (expected $want, got $got)"
    say "SHA-256 verified ($got)"
    tar -xzf "$tmp/$name" -C "$tmp" xref
    dir=$(install_dir)
    mkdir -p "$dir" 2>/dev/null || die "cannot create $dir; set XREF_INSTALL_DIR or run with sudo"
    [ -w "$dir" ] || die "$dir is not writable; set XREF_INSTALL_DIR=\$HOME/.local/bin or run with sudo"
    cp "$tmp/xref" "$dir/xref.new" && chmod 755 "$dir/xref.new" && mv -f "$dir/xref.new" "$dir/xref"
    say "installed $dir/xref"
    case ":$PATH:" in *":$dir:"*) ;; *) say "note: $dir is not on PATH; add it, e.g. export PATH=\"$dir:\$PATH\"" ;; esac
    "$dir/xref" --version
}

install_cargo() {
    have cargo || die "cargo not found"
    if [ -n "${XREF_VERSION:-}" ]; then
        say "building with cargo install xref-code --version ${XREF_VERSION#v} --locked"
        cargo install xref-code --version "${XREF_VERSION#v}" --locked
    else
        say "building with cargo install xref-code --locked"
        cargo install xref-code --locked
    fi
    "${CARGO_HOME:-$HOME/.cargo}/bin/xref" --version
}

main() {
    method=${XREF_METHOD:-auto}
    t=$(target)
    case "$method" in
        binary) [ -n "$t" ] || die "no prebuilt binary for $(uname -s) $(uname -m)$( [ "$(uname -s)" = Linux ] && echo ' (needs x86-64 and glibc >= 2.34)')"
                install_binary "$t" ;;
        cargo) install_cargo ;;
        auto)
            if [ -n "$t" ]; then install_binary "$t"
            elif have cargo; then say "no prebuilt binary for $(uname -s) $(uname -m); building from source"; install_cargo
            else
                die "no prebuilt binary for $(uname -s) $(uname -m) and no cargo. Options:
  - install Rust (https://rustup.rs) and rerun this script, or run: cargo install xref-code --locked
  - Homebrew (macOS Apple Silicon, Linux x86-64): brew install alex09x/apps/xref
  - releases: https://github.com/$REPO/releases"
            fi ;;
        *) die "XREF_METHOD must be auto, binary or cargo (got '$method')" ;;
    esac
}

main "$@"
