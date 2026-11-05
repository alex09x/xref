#!/usr/bin/env python3
# XRef — tests for the social preview renderer
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

SPEC = {"version": "9.9.9", "headline": "See what a thread calls, in order", "subline": "x",
        "page": "live-trace", "example": "What one call of a hot function does"}


class RenderTests(unittest.TestCase):
    def test_terminal_comes_from_the_recorded_page(self):
        command, lines = render.example("live-trace", "What one call of a hot function does")
        self.assertTrue(command.startswith("sudo xref -b rg live trace"))
        page = (render.ROOT / "docs/cli/live-trace.md").read_text()
        self.assertTrue(all(line in page for line in lines))

    def test_fit_bounds_rows_and_columns_and_marks_the_cut(self):
        rows = render.fit("xref " + "a" * 100, [f"line {i}" for i in range(40)])
        self.assertEqual(len(rows), render.MAX_LINES)
        self.assertTrue(all(len(text) <= render.MAX_COLS for _, text in rows))
        self.assertEqual(rows[-1], ("cut", f"… {40 - (render.MAX_LINES - 2)} more lines"))

    def test_keep_filters_lines(self):
        rows = render.fit("xref x", ["a 1", "b 2", "a 3"], keep="^a")
        self.assertEqual([t for _, t in rows[1:]], ["a 1", "a 3"])

    def test_unknown_example_and_long_headline_are_refused(self):
        with self.assertRaises(ValueError):
            render.example("live-trace", "No such example")
        with self.assertRaises(ValueError):
            render.check_spec({**SPEC, "headline": "x" * 49})

    def test_example_without_a_recording_never_borrows_the_next_one(self):
        recorded = "```console\n$ xref -b rg stats\n```\n\n```text output\nfunctions 1\n```\n"
        page = f"### Empty\n\nprose only\n\n### Recorded\n\n{recorded}"
        with self.assertRaises(ValueError):
            render.example_in(page, "Empty", "p")
        self.assertEqual(render.example_in(page, "Recorded", "p"), ("xref -b rg stats", ["functions 1"]))

    def test_hash_lines_inside_code_do_not_end_the_section(self):
        page = ("### A\n\n```sh\n# a shell comment\n```\n\n"
                "```console\n$ xref -b rg stats\n```\n\n```text output\n# not a heading\n```\n\n## Next\n")
        self.assertEqual(render.example_in(page, "A", "p"), ("xref -b rg stats", ["# not a heading"]))

    def test_html_escapes_and_fills_every_placeholder(self):
        page = render.build_html({**SPEC, "subline": "<b>&</b>"})
        self.assertIn("&lt;b&gt;&amp;&lt;/b&gt;", page)
        self.assertNotRegex(page, r"\{(logo|pills|headline|subline|source|terminal)\}")


if __name__ == "__main__":
    unittest.main()
