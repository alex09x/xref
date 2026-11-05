#!/usr/bin/env python3
# XRef — tests for the /docs/ Markdown renderer
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import md  # noqa: E402

md.SITE_PAGES.update({"live", "mcp"})


class RenderTests(unittest.TestCase):
    def test_links_to_guides_pages_and_repository_files(self):
        self.assertEqual(md.link_target("live.md#trace", "mcp"), "/docs/live#trace")
        self.assertEqual(md.link_target("live-walkthrough.md", "mcp"), "/live-walkthrough")
        self.assertEqual(md.link_target("release-automation.md", "mcp"),
                         "https://github.com/alex09x/xref/blob/main/docs/release-automation.md")
        self.assertEqual(md.link_target("../src/cli.rs", "mcp"), "https://github.com/alex09x/xref/blob/main/src/cli.rs")
        self.assertEqual(md.link_target("https://example.org/x", "mcp"), "https://example.org/x")

    def test_html_is_escaped_and_never_passed_through(self):
        body, _ = md.render("# T\n\nA <script>x</script> & `<b>`\n", "p")
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("<code>&lt;b&gt;</code>", body)
        self.assertNotIn("<script>", body)

    def test_nested_lists_tables_fences_and_alerts(self):
        src = "# T\n\n- a\n  - b\n- c\n\n| x | y |\n| - | - |\n| 1 | 2 |\n\n```sh\nxref -b a stats\n```\n\n> [!NOTE]\n> hi\n"
        body, toc = md.render(src, "p")
        self.assertIn("<ul><li>a<ul><li>b</li></ul></li><li>c</li></ul>", body)
        self.assertIn("<td>1</td><td>2</td>", body)
        self.assertIn('data-lang="sh">xref -b a stats</pre>', body)
        self.assertIn("doc-alert-note", body)
        self.assertEqual(toc, [])

    def test_heading_anchors_are_unique_and_listed(self):
        body, toc = md.render("# T\n\n## Run `xref`\n\n## Run `xref`\n\n### Sub\n", "p")
        self.assertEqual([a for _, a, _ in toc], ["run-xref", "run-xref-1", "sub"])
        self.assertIn('<h2 id="run-xref-1">', body)


if __name__ == "__main__":
    unittest.main()
