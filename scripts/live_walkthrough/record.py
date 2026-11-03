#!/usr/bin/env python3
# XRef — Live Analysis walkthrough recorder (runs real xref live commands against our own fixture daemon)
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Record the Live Analysis walkthrough on a Linux x86-64 host.

Builds nothing itself: expects `target/release/xref` from the current checkout. Compiles the
stripped fixture `tests/fixtures/live_daemon_app.rs`, starts it, and runs a fixed chain of
`xref live` / static commands. Every command is executed exactly as recorded (cwd is the work
directory, so commands read `./xref` and `vault-daemon`). Addresses are derived from the previous
step's real stdout, because every rebuild of the fixture can move functions.

Privileged steps (`probe`, `watch`) use `sudo -n` and only target the fixture started here.
Writes a JSON transcript consumed by `render.py`.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time

from parse import first_ref_function, heap_hit_rows, row_at, static_fn_of, static_of_resolved

WORK = "/tmp/xref-walkthrough"
SIG = ("0x4441454d4f4e5632", "0x778899aabbccddee")  # DaemonVault signature words
EXT_SIG = ("0x5852454654595045", "0x1122334455667788")  # RichTypeMirror signature words
READY_TIMEOUT_S = 10.0
OBSERVER_DEADLINE_S = 90.0


def stop_observer(proc, argv):
    """Stop the observer's process group (via `sudo -n kill` when it runs under sudo) and reap it."""
    for sig in ("TERM", "KILL"):
        if proc.poll() is not None:
            return
        if argv[0] == "sudo":
            subprocess.run(["sudo", "-n", "kill", f"-{sig}", "--", f"-{proc.pid}"], capture_output=True, timeout=10)
        else:
            try:
                os.killpg(proc.pid, getattr(signal, f"SIG{sig}"))
            except ProcessLookupError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def tool_version(argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True).stdout.strip()


class Daemon:
    def __init__(self):
        self.proc = subprocess.Popen(
            ["./vault-daemon"], cwd=WORK, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        self.banner = self.proc.stdout.readline().strip()
        if not self.banner.startswith("DAEMON_READY pid="):
            raise SystemExit(f"unexpected daemon banner: {self.banner!r}")
        self.pid = str(self.proc.pid)

    def send(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline().strip()

    def quit(self):
        reply = self.send("QUIT")
        self.proc.wait(timeout=5)
        return reply


class Recorder:
    def __init__(self, daemon):
        self.daemon = daemon
        self.steps = []

    def run(self, step_id, argv, daemon_cmds=()):
        """Run a short command; optional daemon commands are sent (and recorded) first."""
        io = [{"send": c, "reply": self.daemon.send(c)} for c in daemon_cmds]
        res = subprocess.run(argv, cwd=WORK, capture_output=True, text=True, timeout=60)
        return self._add(step_id, argv, res.stdout, res.stderr, res.returncode, io)

    def armed(self, step_id, argv, daemon_cmds, gap_s=0.08, deadline_s=OBSERVER_DEADLINE_S):
        """Run an observer; send daemon commands only after its `*_ready` receipt on stderr.

        stdout and stderr are drained by threads, so the only blocking wait is `proc.wait` with a
        deadline. On timeout or any error the observer's own process group is stopped and reaped."""
        proc = subprocess.Popen(argv, cwd=WORK, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
        err_lines, out_chunks, ready = [], [], threading.Event()

        def drain_err():
            for line in proc.stderr:
                err_lines.append(line)
                if line.startswith("xref: probe_ready ") or line.startswith("xref: watch_ready "):
                    ready.set()

        def drain_out():
            out_chunks.append(proc.stdout.read())

        readers = [threading.Thread(target=fn, daemon=True) for fn in (drain_err, drain_out)]
        for reader in readers:
            reader.start()
        try:
            if not ready.wait(READY_TIMEOUT_S):
                raise SystemExit(f"{step_id}: observer never reported ready: {''.join(err_lines)}")
            io = []
            for cmd in daemon_cmds:
                io.append({"send": cmd, "reply": self.daemon.send(cmd)})
                time.sleep(gap_s)
            try:
                proc.wait(timeout=deadline_s)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"{step_id}: observer still running after {deadline_s}s") from None
        except BaseException:
            stop_observer(proc, argv)
            raise
        finally:
            for reader in readers:
                reader.join(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                stream.close()
        return self._add(step_id, argv, "".join(out_chunks), "".join(err_lines), proc.returncode, io)

    def _add(self, step_id, argv, out, err, code, io):
        if code != 0:
            raise SystemExit(f"{step_id} failed ({code}): {' '.join(argv)}\n{err}")
        self.steps.append({"id": step_id, "argv": argv, "stdout": out, "stderr": err, "exit": code, "daemon_io": io})
        return out


def prepare(repo, commit):
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    shutil.copy2(os.path.join(repo, "target/release/xref"), os.path.join(WORK, "xref"))
    src = os.path.join(repo, "tests/fixtures/live_daemon_app.rs")
    rustc = ["rustc", "--edition=2021", "-O", "-C", "strip=symbols", "-o", "vault-daemon", src]
    subprocess.run(rustc, cwd=WORK, check=True)
    return {
        "xref_commit": commit,
        "xref_version": tool_version([os.path.join(WORK, "xref"), "--version"]),
        "xref_sha256": sha256(os.path.join(WORK, "xref")),
        "rustc": tool_version(["rustc", "--version"]),
        "fixture_build": "rustc --edition=2021 -O -C strip=symbols -o vault-daemon tests/fixtures/live_daemon_app.rs",
        "fixture_source_sha256": sha256(src),
        "fixture_sha256": sha256(os.path.join(WORK, "vault-daemon")),
        "kernel": f"{platform.system()} {platform.release()} {platform.machine()}",
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def record(rec, pid):
    x, b = "./xref", "vault-daemon"
    rec.run("maps", [x, "-b", b, "live", "maps", "--pid", pid])
    scan = rec.run("memscan", [x, "-b", b, "live", "memscan", "--pid", pid, "--after-words", "11", *SIG])
    rows = heap_hit_rows(scan)
    hook_ptr = row_at(rows, "+0x38")["value"]
    label_ptr = row_at(rows, "+0x60")["value"]
    sealed_slot = row_at(rows, "+0x28")["va"]
    resolved = rec.run("resolve", [x, "-b", b, "live", "resolve", "--pid", pid, hook_ptr, label_ptr])
    hook_fn = static_fn_of(row_at(rows, "+0x38"))
    label_va = static_of_resolved(resolved, label_ptr)
    refs = rec.run("refs", [x, "-b", b, "refs", label_va])
    deposit_fn = first_ref_function(refs)
    rec.run("c_deposit", [x, "-b", b, "c", deposit_fn])
    rec.run("c_hook", [x, "-b", b, "c", hook_fn])
    probe = ["sudo", "-n", x, "-b", b, "live", "probe", "--pid", pid, "--callers", "--regs", "--duration-ms", "1500"]
    rec.armed("probe", [*probe, deposit_fn, hook_fn], ["DEPOSIT 777 250000", "ROTATE 0x99", "DEPOSIT 777 125000"])
    watch = ["sudo", "-n", x, "-b", b, "live", "watch", "--pid", pid, "--duration-ms", "1200"]
    rec.armed("watch", [*watch, sealed_slot], ["DEPOSIT 777 1000", "DEPOSIT 777 2000"])
    rich = rec.run("memscan_rich", [x, "-b", b, "live", "memscan", "--pid", pid, "--after-words", "12", *EXT_SIG])
    rrows = heap_hit_rows(rich)
    follow = (
        f"ptr_slot={row_at(rrows, '+0x50')['va']},offset=0,len_slot={row_at(rrows, '+0x60')['va']},min_len=1,"
        f"guard_slot={row_at(rrows, '0x0')['va']},guard_val={EXT_SIG[0]}"
    )
    rec.armed(
        "follow",
        [*watch[:-1], "1600", "--follow", follow],
        ["VEC_WRITE0 0x1111222233334444", "VEC_MOVE_WRITE0 0x5555666677778888", "VEC_WRITE0 0x9999aaaabbbbcccc"],
    )
    return {"hook_fn": hook_fn, "deposit_fn": deposit_fn, "label_va": label_va}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--commit", required=True, help="git commit the xref binary was built from")
    ap.add_argument("--out", required=True, help="transcript JSON path")
    args = ap.parse_args()
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise SystemExit("the walkthrough must be recorded on Linux x86-64")
    meta = prepare(os.path.abspath(args.repo), args.commit)
    daemon = Daemon()
    rec = Recorder(daemon)
    try:
        start_io = [{"send": "DEPOSIT 777 500000", "reply": daemon.send("DEPOSIT 777 500000")}]
        derived = record(rec, daemon.pid)
    finally:
        bye = daemon.quit() if daemon.proc.poll() is None else None
    doc = {"meta": meta, "pid": daemon.pid, "banner": daemon.banner, "start_io": start_io, "bye": bye,
           "derived": derived, "steps": rec.steps}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    print(f"recorded {len(rec.steps)} steps -> {args.out}")


if __name__ == "__main__":
    main()
