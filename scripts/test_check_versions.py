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

    def test_missing_markers_and_pins_are_reported(self):
        import tempfile, shutil
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("docs/recorded-data.js", "docs/index.html", "scripts/live_walkthrough/transcript.json",
                        "docs/live-walkthrough.md", "docs/live-walkthrough.html"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(cv.ROOT / rel, root / rel)
            (root / "docs/cli").mkdir()
            (root / "docs/cli/a.md").write_text("<!-- xref:run -->\nno marker\n")
            (root / "docs/cli/b.md").write_text("syntax only\n")
            (root / "docs/walkthroughs/w").mkdir(parents=True)
            with mock.patch.object(cv, "ROOT", root), mock.patch.object(cv, "PINNED", {"docs/gone.txt": ("1.0.0", "r")}):
                stale = {i["path"]: i for i in cv.recordings() if i["version"] == "?"}
        self.assertIn("docs/cli/a.md", stale)
        self.assertNotIn("docs/cli/b.md", stale)
        self.assertIn("docs/walkthroughs/w/environment.txt", stale)
        self.assertIn("docs/gone.txt", stale)

    def test_social_meta_must_be_present_recognized_and_on_disk(self):
        def page(og, tw):
            meta = lambda p, v: f'<meta {p} content="https://xrefcode.com/{v}" />' if v else ""  # noqa: E731
            return meta('property="og:image"', og) + meta('name="twitter:image"', tw)
        ok_name = "og-v0.4.0-trace.png"
        good = cv.social_images(page(ok_name, ok_name))
        self.assertEqual([i["version"] for i in good], ["0.4.0", "0.4.0"])
        for og, tw in [(None, ok_name), (ok_name, None),                       # a meta removed
                       ("og-v0.4.0-TRACE.png", ok_name),                      # uppercase variant
                       ("og-v0.4.0.foo.png", ok_name),                        # unrecognized name
                       ("og-v0.4.0--x.png", ok_name),                         # empty dash segment
                       ("og-v0.4.0-nope.png", "og-v0.4.0-nope.png")]:         # not on disk
            items = cv.social_images(page(og, tw))
            self.assertTrue(any(i["version"] == "?" for i in items), (og, tw))
        doubled = page(ok_name, ok_name) + page(ok_name, None)
        self.assertTrue(any(i["version"] == "?" for i in cv.social_images(doubled)))

    def test_repository_is_current(self):
        version = cv.current_version()
        self.assertEqual(cv.problems(cv.recordings() + cv.links(), version), [])


if __name__ == "__main__":
    unittest.main()
