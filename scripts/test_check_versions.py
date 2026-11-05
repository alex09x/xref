#!/usr/bin/env python3
# XRef — tests for the version freshness check
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_versions as cv  # noqa: E402


def item(path, version):
    return cv.found(path, version, "x")


class ProblemTests(unittest.TestCase):
    def test_current_version_passes_and_older_fails(self):
        self.assertEqual(cv.problems([item("a", "1.2.0")], "1.2.0"), [])
        self.assertEqual(len(cv.problems([item("a", "1.1.0")], "1.2.0")), 1)

    def test_pinned_record_passes_only_at_its_pinned_version(self):
        path = next(iter(cv.PINNED))
        pinned = cv.PINNED[path][0]
        self.assertEqual(cv.problems([item(path, pinned)], "99.0.0"), [])
        self.assertEqual(len(cv.problems([item(path, "0.0.1")], "99.0.0")), 1)

    def test_unknown_marker_always_fails(self):
        self.assertEqual(len(cv.problems([item("a", "?")], "1.0.0")), 1)

    def test_repository_is_current(self):
        version = cv.current_version()
        self.assertEqual(cv.problems(cv.recordings() + cv.links(), version), [])


if __name__ == "__main__":
    unittest.main()
