# XRef — release publication regression tests
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import channels
import github_release as release

TAG = "v0.3.0"
SHA = "a" * 40


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in release.archive_names(TAG):
            (self.root / name).write_bytes(name.encode())
            checksum = release.digest(self.root / name)
            (self.root / f"{name}.sha256").write_text(f"{checksum}  {name}\n")

    def test_manifest_verifies_source_and_detects_modified_archive(self):
        release.prepare(self.root, TAG, SHA)
        self.assertEqual(release.verify_files(self.root, TAG, SHA)["git_sha"], SHA)
        with self.assertRaisesRegex(ValueError, "different source identity"):
            release.verify_files(self.root, TAG, "b" * 40)
        (self.root / release.archive_names(TAG)[0]).write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "archive mismatch"):
            release.verify_files(self.root, TAG, SHA)

    def test_prepare_rejects_bad_checksum(self):
        name = release.archive_names(TAG)[0]
        (self.root / f"{name}.sha256").write_text("bad\n")
        with self.assertRaisesRegex(ValueError, "sidecar mismatch"):
            release.prepare(self.root, TAG, SHA)

    @patch.object(release, "verify_public")
    @patch.object(release, "release_info", return_value={"draft": False})
    @patch.object(release, "gh")
    def test_existing_public_release_is_verified_without_upload(self, gh, _info, verify):
        release.prepare(self.root, TAG, SHA)
        release.publish(self.root, TAG, SHA)
        verify.assert_called_once_with(TAG, SHA, self.root)
        gh.assert_not_called()

    @patch.object(release, "gh")
    def test_only_a_real_404_is_treated_as_missing(self, run):
        # A registry/GitHub auth or network failure must not become "new release".
        run.side_effect = RuntimeError("HTTP 403")
        with self.assertRaisesRegex(RuntimeError, "403"):
            release.release_info(TAG, missing_ok=True)

    @patch.object(channels, "fetch")
    def test_homebrew_requires_each_platform_hash_and_version(self, fetch):
        manifest = release.prepare(self.root, TAG, SHA)
        formula = 'class Xref < Formula\n  version "0.3.0"\n'
        for entry in manifest["archives"]:
            formula += f'  url "https://github.com/alex09x/xref/releases/download/{TAG}/{entry["name"]}"\n'
            formula += f'  sha256 "{entry["sha256"]}"\n'
        fetch.side_effect = [(json.dumps(manifest).encode(), {}), (formula.encode(), {})]
        self.assertEqual(channels.check_homebrew(TAG)["tag"], TAG)
        corrupt = formula.replace(manifest["archives"][0]["sha256"], "0" * 64)
        fetch.side_effect = [(json.dumps(manifest).encode(), {}), (corrupt.encode(), {})]
        with self.assertRaisesRegex(ValueError, "URL/hash mismatch"):
            channels.check_homebrew(TAG)

    @patch.object(channels, "fetch")
    def test_site_requires_security_headers_and_tagged_og_bytes(self, fetch):
        html = b'{"softwareVersion":"0.3.0"} v0.3.0/xref-v0.3.0-x86_64-unknown-linux-gnu.tar.gz https://xrefcode.com/og-v0.3.0.png'
        fetch.return_value = (html, {})
        with self.assertRaisesRegex(ValueError, "CSP or HSTS"):
            channels.check_site(TAG)
        headers = {"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=1"}
        fetch.side_effect = [(html, headers), (b"bad image", {})]
        with patch.object(Path, "read_bytes", return_value=b"tagged image"):
            with self.assertRaisesRegex(ValueError, "social image differs"):
                channels.check_site(TAG)


if __name__ == "__main__":
    unittest.main()
