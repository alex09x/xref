#!/usr/bin/env python3
# XRef — tests for the /docs/ completeness check
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build  # noqa: E402


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.docs, self.out = root / "docs", root / "docs" / "docs"
        self.out.mkdir(parents=True)
        for name in ("live", "mcp", "release-automation"):
            (self.docs / f"{name}.md").write_text(f"# {name}\n", encoding="utf-8")
        self.page = self.out / "live.html"
        self.page.write_text("ok", encoding="utf-8")
        self.rendered = {self.page: "ok"}

    def tearDown(self):
        self.tmp.cleanup()

    def test_listed_and_excluded_guides_pass(self):
        self.assertEqual(build.problems(self.rendered, self.out, self.docs), [])

    def test_new_guide_missing_from_groups_fails(self):
        (self.docs / "new-guide.md").write_text("# New\n", encoding="utf-8")
        found = build.problems(self.rendered, self.out, self.docs)
        self.assertTrue(any("docs/new-guide.md is not listed" in p for p in found), found)

    def test_unexpected_nested_file_fails(self):
        nested = self.out / "old" / "page.html"
        nested.parent.mkdir()
        nested.write_text("x", encoding="utf-8")
        found = build.problems(self.rendered, self.out, self.docs)
        self.assertTrue(any("unexpected file" in p and "page.html" in p for p in found), found)

    def test_stale_page_fails(self):
        self.page.write_text("old", encoding="utf-8")
        self.assertTrue(any("stale or missing" in p for p in build.problems(self.rendered, self.out, self.docs)))


if __name__ == "__main__":
    unittest.main()
