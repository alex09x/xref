#!/usr/bin/env python3
# XRef — tests for the command reference recorder
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import record  # noqa: E402


class NormalizeTests(unittest.TestCase):
    def test_strips_only_line_end_whitespace_and_trailing_empty_lines(self):
        raw = "  void f() {\t\n\n    x = 1;   \n  }\n\n\n"
        self.assertEqual(record.normalize(raw), "  void f() {\n\n    x = 1;\n  }")

    def test_keeps_leading_and_inner_whitespace(self):
        raw = '0x10  "a  b "  \n\t- item\n'
        self.assertEqual(record.normalize(raw), '0x10  "a  b "\n\t- item')

    def test_empty_and_blank_output_become_empty(self):
        self.assertEqual(record.normalize(""), "")
        self.assertEqual(record.normalize(" \n\n"), "")

    def test_provenance_states_the_normalization(self):
        self.assertIn("whitespace at the end of each line", record.NORMALIZATION)
        self.assertIn("empty lines at the end", record.NORMALIZATION)
        self.assertNotIn("Output is unchanged;", record.NORMALIZATION)


if __name__ == "__main__":
    unittest.main()
