#!/usr/bin/env python3
# XRef — Live Analysis walkthrough: unprivileged regression tests for the recorder
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fake observers (plain Python, no perf access) exercise `Recorder.armed` deadlines and cleanup."""

import os
import signal
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import record  # noqa: E402

READY_THEN = (
    "import os, sys, time\n"
    "open(sys.argv[1], 'w').write(str(os.getpid()))\n"
    "sys.stderr.write('xref: watch_ready {}\\n'); sys.stderr.flush()\n"
)


class FakeDaemon:
    def __init__(self):
        self.sent = []

    def send(self, line):
        self.sent.append(line)
        return f"ACK {line}"


def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


class ArmedObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old_work, record.WORK = record.WORK, self.tmp.name
        self.addCleanup(setattr, record, "WORK", self.old_work)
        self.pid_file = os.path.join(self.tmp.name, "observer.pid")
        self.rec = record.Recorder(FakeDaemon())

    def observer(self, body):
        return [sys.executable, "-c", READY_THEN + body, self.pid_file]

    def test_hanging_observer_with_open_stdout_hits_deadline_and_is_reaped(self):
        argv = self.observer("time.sleep(60)\n")
        started = time.monotonic()
        with self.assertRaises(SystemExit) as caught:
            self.rec.armed("hang", argv, ["PING"], gap_s=0, deadline_s=0.5)
        self.assertLess(time.monotonic() - started, 15, "deadline must bound the capture")
        self.assertIn("still running", str(caught.exception))
        with open(self.pid_file, encoding="utf-8") as fh:
            self.assertTrue(gone(int(fh.read())), "observer must be killed and reaped")
        self.assertEqual(self.rec.daemon.sent, ["PING"])
        self.assertEqual(self.rec.steps, [])

    def test_observer_that_never_becomes_ready_is_reaped(self):
        argv = [sys.executable, "-c", "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)",
                self.pid_file]
        old_ready, record.READY_TIMEOUT_S = record.READY_TIMEOUT_S, 0.5
        self.addCleanup(setattr, record, "READY_TIMEOUT_S", old_ready)
        with self.assertRaises(SystemExit) as caught:
            self.rec.armed("never", argv, ["PING"], gap_s=0, deadline_s=5)
        self.assertIn("never reported ready", str(caught.exception))
        with open(self.pid_file, encoding="utf-8") as fh:
            self.assertTrue(gone(int(fh.read())))
        self.assertEqual(self.rec.daemon.sent, [], "no daemon command before ready")

    def test_completed_observer_output_is_recorded(self):
        argv = self.observer("print('report line'); sys.stdout.flush()\n")
        out = self.rec.armed("ok", argv, ["PING"], gap_s=0, deadline_s=10)
        self.assertEqual(out, "report line\n")
        step = self.rec.steps[0]
        self.assertEqual((step["id"], step["exit"], step["daemon_io"]), ("ok", 0, [{"send": "PING", "reply": "ACK PING"}]))
        self.assertIn("xref: watch_ready {}", step["stderr"])

    def child_holding_pipes(self, escape_group):
        child_pid_file = os.path.join(self.tmp.name, "child.pid")
        setsid = "os.setsid(); " if escape_group else ""
        child = f"import os, sys, time; {setsid}open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
        body = (
            "import subprocess\n"
            f"subprocess.Popen([sys.executable, '-c', {child!r}, {child_pid_file!r}])\n"
            f"while not os.path.exists({child_pid_file!r}): time.sleep(0.01)\n"
            "print('leader done'); sys.stdout.flush()\n"
        )
        return self.observer(body), child_pid_file

    def test_leader_exits_while_child_in_its_group_holds_pipes(self):
        argv, child_pid_file = self.child_holding_pipes(escape_group=False)
        started = time.monotonic()
        out = self.rec.armed("inherit", argv, [], gap_s=0, deadline_s=10, reader_grace_s=0.3)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(out, "leader done\n")
        with open(child_pid_file, encoding="utf-8") as fh:
            child_pid = int(fh.read())
        deadline = time.monotonic() + 5
        while not gone(child_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(gone(child_pid), "the group member holding the pipes must be stopped")

    def test_descendant_outside_the_group_cannot_block_the_recorder(self):
        argv, child_pid_file = self.child_holding_pipes(escape_group=True)
        started = time.monotonic()
        try:
            with self.assertRaises(SystemExit) as caught:
                self.rec.armed("escaped", argv, [], gap_s=0, deadline_s=10, reader_grace_s=0.3)
            self.assertLess(time.monotonic() - started, 30, "cleanup must stay bounded")
            self.assertIn("pipes still open", str(caught.exception))
        finally:
            with open(child_pid_file, encoding="utf-8") as fh:
                os.kill(int(fh.read()), signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
