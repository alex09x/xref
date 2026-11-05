# XRef — tests for the Homebrew formula renderer
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0
import unittest
from pathlib import Path

import homebrew_formula as hf

TEMPLATE = (Path(__file__).resolve().parents[2] / "packaging/homebrew/xref.rb.in").read_text(encoding="utf-8")


def manifest(tag):
    return {
        "tag": tag,
        "version": tag[1:],
        "archives": [
            {"name": f"xref-{tag}-aarch64-apple-darwin.tar.gz", "sha256": "a" * 64},
            {"name": f"xref-{tag}-x86_64-unknown-linux-gnu.tar.gz", "sha256": "b" * 64},
        ],
    }


class HomebrewFormulaTests(unittest.TestCase):
    def test_renders_version_urls_and_hashes(self):
        text = hf.render("v0.4.0", manifest("v0.4.0"), TEMPLATE)
        self.assertEqual(hf.formula_version(text), (0, 4, 0))
        self.assertIn('url "https://github.com/alex09x/xref/releases/download/v0.4.0/'
                      'xref-v0.4.0-aarch64-apple-darwin.tar.gz"', text)
        self.assertIn('sha256 "' + "b" * 64 + '"', text)
        self.assertNotIn("@@", text)

    def test_rerun_of_older_release_keeps_newer_formula(self):
        current = hf.update("v0.4.0", manifest("v0.4.0"), TEMPLATE, None)
        self.assertIsNone(hf.update("v0.3.0", manifest("v0.3.0"), TEMPLATE, current))

    def test_same_or_newer_release_rewrites(self):
        current = hf.render("v0.4.0", manifest("v0.4.0"), TEMPLATE)
        self.assertEqual(hf.update("v0.4.0", manifest("v0.4.0"), TEMPLATE, current), current)
        self.assertEqual(hf.formula_version(hf.update("v0.10.0", manifest("v0.10.0"), TEMPLATE, current)), (0, 10, 0))

    def test_rejects_mismatched_manifest(self):
        with self.assertRaises(ValueError):
            hf.render("v0.4.0", manifest("v0.3.0"), TEMPLATE)

    def test_unparseable_existing_formula_is_not_overwritten(self):
        for current in ("", "class Xref < Formula\n  version '0.9.0'\nend\n", "class Xref < Formula\nend\n"):
            with self.assertRaises(ValueError):
                hf.update("v0.4.0", manifest("v0.4.0"), TEMPLATE, current)

    def test_rejects_prerelease_draft_and_non_stable_tags(self):
        hf.check_release("v0.4.0", {"tagName": "v0.4.0", "isDraft": False, "isPrerelease": False})
        for release in ({"tagName": "v0.4.0", "isDraft": False, "isPrerelease": True},
                        {"tagName": "v0.4.0", "isDraft": True, "isPrerelease": False},
                        {"tagName": "v0.4.0"},
                        {"tagName": "v0.3.0", "isDraft": False, "isPrerelease": False}):
            with self.assertRaises(ValueError):
                hf.check_release("v0.4.0", release)
        for tag in ("v0.4.0-rc1", "0.4.0", "v0.4", "main"):
            with self.assertRaises(ValueError):
                hf.check_release(tag, {"tagName": tag, "isDraft": False, "isPrerelease": False})


if __name__ == "__main__":
    unittest.main()
