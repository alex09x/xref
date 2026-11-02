#!/usr/bin/env python3
# XRef Code — README rendering regression checks
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Exercise translation checks with the GitHub rendering regressions."""

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "translations", ROOT / "scripts/check-readme-translations.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
CANONICAL = (ROOT / "README.md").read_text(encoding="utf-8")
SOURCE = ROOT / "readme/README.de.md"
TRANSLATION = SOURCE.read_text(encoding="utf-8")
LICENSE_URL = "http://opensource.org/licenses/MIT"


class RenderingChecks(unittest.TestCase):
    def errors_for(self, text):
        with patch.object(Path, "read_text", return_value=text):
            return CHECKER.check(SOURCE, CANONICAL)

    def test_rejects_unicode_punctuation_in_external_url(self):
        text = TRANSLATION.replace(LICENSE_URL, LICENSE_URL + "）")
        self.assertTrue(any("external URL" in e for e in self.errors_for(text)))

    def test_rejects_missing_canonical_external_url(self):
        text = TRANSLATION.replace(LICENSE_URL, "License page")
        self.assertTrue(any("external URL" in e for e in self.errors_for(text)))

    def test_accepts_explicit_autolink_next_to_unicode_punctuation(self):
        text = TRANSLATION.replace(LICENSE_URL, "（<" + LICENSE_URL + ">）")
        self.assertEqual(self.errors_for(text), [])

    def test_rejects_each_github_alert_inside_html_div(self):
        for kind in ("NOTE", "TIP", "IMPORTANT", "WARNING", "CAUTION"):
            with self.subTest(kind=kind):
                text = f'<div dir="rtl">\n\n> [!{kind}]\n> Note\n\n</div>\n' + TRANSLATION
                self.assertTrue(any("alert inside" in e for e in self.errors_for(text)))

    def test_accepts_top_level_alert_before_direction_container(self):
        text = '> [!NOTE]\n> Note\n\n<div dir="rtl">\n\n</div>\n' + TRANSLATION
        self.assertEqual(self.errors_for(text), [])

    def test_ignores_html_div_mentioned_in_inline_code(self):
        text = '`<div>`\n\n> [!NOTE]\n> Note\n\n' + TRANSLATION
        self.assertEqual(self.errors_for(text), [])


if __name__ == "__main__":
    unittest.main()
