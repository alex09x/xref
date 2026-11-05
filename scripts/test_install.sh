#!/usr/bin/env bash
# XRef — tests for docs/install.sh (no network: curl, cp and chmod are replaced where needed)
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=${XREF_INSTALL_SCRIPT:-"$ROOT/docs/install.sh"}
WORK=$(mktemp -d)
trap 'kill "${SERVER:-}" 2>/dev/null; rm -rf "$WORK"' EXIT
FAILED=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; FAILED=1; }

case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) TARGET=x86_64-unknown-linux-gnu ;;
    Darwin/arm64) TARGET=aarch64-apple-darwin ;;
    *) echo "skip: no release target for this host"; exit 0 ;;
esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'; }

# A fake release v9.9.9 served by a fake curl that logs its arguments.
REL="$WORK/release"; BIN="$WORK/bin"; mkdir -p "$REL" "$BIN" "$WORK/pkg"
printf '#!/bin/sh\necho "xref 9.9.9"\n' > "$WORK/pkg/xref"; chmod 755 "$WORK/pkg/xref"
NAME="xref-v9.9.9-$TARGET.tar.gz"
tar -czf "$REL/$NAME" -C "$WORK/pkg" xref
echo "$(sha "$REL/$NAME")  $NAME" > "$REL/$NAME.sha256"
cat > "$BIN/curl" <<EOF
#!/bin/sh
echo "\$*" >> "$WORK/curl.log"
out=""; url=""
while [ \$# -gt 0 ]; do case "\$1" in -o) out=\$2; shift ;; https://*) url=\$1 ;; esac; shift; done
[ -f "$REL/\${url##*/}" ] || exit 22
/bin/cp "$REL/\${url##*/}" "\$out"   # absolute: the tests below replace cp on PATH
EOF
chmod 755 "$BIN/curl"

old_install() { mkdir -p "$1"; printf '#!/bin/sh\necho "xref 0.0.1"\n' > "$1/xref"; chmod 755 "$1/xref"; }
run() { PATH="$1:$PATH" XREF_VERSION=v9.9.9 XREF_INSTALL_DIR="$2" sh "$SCRIPT" > "$WORK/out" 2>&1; }

# 1. A good release installs, and every curl call forbids non-HTTPS for the request and redirects.
D="$WORK/d1"; old_install "$D"; : > "$WORK/curl.log"
if run "$BIN" "$D" && [ "$("$D/xref")" = "xref 9.9.9" ]; then ok "installs a verified release over an older one"; else bad "install"; cat "$WORK/out"; fi
if [ -s "$WORK/curl.log" ] && ! grep -v -- '--proto =https --proto-redir =https' "$WORK/curl.log" >/dev/null; then
    ok "every curl call has --proto =https --proto-redir =https"; else bad "curl flags"; cat "$WORK/curl.log"; fi

# 2. cp or chmod failing: non-zero exit, no 'installed', old binary untouched, no temp file left.
for tool in cp chmod; do
    F="$WORK/fail-$tool"; mkdir -p "$F"; cp "$BIN/curl" "$F/curl"
    printf '#!/bin/sh\nexit 1\n' > "$F/$tool"; chmod 755 "$F/$tool"
    D="$WORK/d-$tool"; old_install "$D"
    if run "$F" "$D"; then bad "$tool failure exits 0"
    elif ! grep -q 'SHA-256 verified' "$WORK/out"; then bad "$tool test failed before the install step"; cat "$WORK/out"
    elif grep -q 'installed' "$WORK/out"; then bad "$tool failure still says installed"
    elif [ "$("$D/xref")" != "xref 0.0.1" ] || [ -e "$D/xref.new" ]; then bad "$tool failure changed the install dir"
    else ok "$tool failure stops with an error and keeps the old binary"; fi
done

# 3. A checksum that does not match: refused, nothing installed.
echo "0000000000000000000000000000000000000000000000000000000000000000  $NAME" > "$REL/$NAME.sha256"
D="$WORK/d3"; old_install "$D"
if ! run "$BIN" "$D" && grep -q 'SHA-256 mismatch' "$WORK/out" && [ "$("$D/xref")" = "xref 0.0.1" ]; then
    ok "checksum mismatch is refused"; else bad "checksum mismatch"; cat "$WORK/out"; fi

# 4. cargo path: the binary cargo reports (here under CARGO_INSTALL_ROOT) is the one run, not ~/.cargo/bin.
C="$WORK/cargo-bin"; mkdir -p "$C" "$WORK/home/.cargo/bin" "$WORK/croot"
printf '#!/bin/sh\necho "xref 0.0.1"\n' > "$WORK/home/.cargo/bin/xref"; chmod 755 "$WORK/home/.cargo/bin/xref"
cat > "$C/cargo" <<'EOF'
#!/bin/sh
[ -n "${FAKE_CARGO_FAIL:-}" ] && { echo "error: could not compile" >&2; exit 101; }
mkdir -p "$CARGO_INSTALL_ROOT/bin"
printf '#!/bin/sh\necho "xref 9.9.9-cargo"\n' > "$CARGO_INSTALL_ROOT/bin/xref"; chmod 755 "$CARGO_INSTALL_ROOT/bin/xref"
echo "  Installing xref-code v9.9.9" >&2
echo "  Installing $CARGO_INSTALL_ROOT/bin/xref" >&2
echo "   Installed package \`xref-code v9.9.9\` (executable \`xref\`)" >&2
EOF
chmod 755 "$C/cargo"
cargo_run() { PATH="$C:$PATH" HOME="$WORK/home" CARGO_INSTALL_ROOT="$WORK/croot" XREF_METHOD=cargo sh "$SCRIPT" > "$WORK/out" 2>&1; }
if cargo_run && grep -q 'xref 9.9.9-cargo' "$WORK/out" && ! grep -q 'xref 0.0.1' "$WORK/out" \
    && grep -q "installed $WORK/croot/bin/xref" "$WORK/out"; then
    ok "cargo install honours CARGO_INSTALL_ROOT and runs the binary cargo reported"
else bad "cargo install path"; cat "$WORK/out"; fi
if FAKE_CARGO_FAIL=1 cargo_run; then bad "a failing cargo install exits 0"
elif grep -q 'xref 0.0.1' "$WORK/out"; then bad "a failing cargo install ran an old binary"
else ok "a failing cargo install stops with an error"; fi

# 5. Real curl with the installer's flags refuses an HTTPS -> HTTP redirect (local self-signed server).
if command -v openssl >/dev/null && command -v python3 >/dev/null && command -v curl >/dev/null; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 \
        -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
    cat > "$WORK/redirect.py" <<'EOF'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302); self.send_header("Location", "http://127.0.0.1:9/payload"); self.end_headers()
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
s.socket = ctx.wrap_socket(s.socket, server_side=True)
print(s.server_address[1], flush=True); s.serve_forever()
EOF
    python3 "$WORK/redirect.py" "$WORK/cert.pem" "$WORK/key.pem" > "$WORK/port" &
    SERVER=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/port" ] && break; sleep 0.2; done
    URL="https://127.0.0.1:$(cat "$WORK/port")/x"
    # shellcheck source-path=SCRIPTDIR source=../docs/install.sh
    if (XREF_INSTALL_TEST_SOURCE=1 . "$SCRIPT"; CURL_CA_BUNDLE="$WORK/cert.pem" fetch "$URL" "$WORK/got") 2>"$WORK/err"; then
        bad "fetch followed an HTTPS -> HTTP redirect"
    elif grep -q 'download failed' "$WORK/err"; then ok "fetch refuses an HTTPS -> HTTP redirect"
    else bad "redirect test did not run as expected"; cat "$WORK/err"; fi
    # Control: an unrestricted curl does follow the redirect to http (it then fails to connect to port 9),
    # so the refusal above comes from the protocol flags, not from the server.
    curl --cacert "$WORK/cert.pem" -fsSL "$URL" -o /dev/null 2>"$WORK/err2"
    if grep -q '127.0.0.1 port 9\|Failed to connect\|Could not connect' "$WORK/err2"; then
        ok "control: unrestricted curl follows the redirect to http"
    else bad "control did not follow the redirect"; cat "$WORK/err2"; fi
else
    echo "skip: redirect test needs openssl, python3 and curl"
fi

exit $FAILED
