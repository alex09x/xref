# XRef — release publication regression tests
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

import json
from pathlib import Path
import shutil
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

    def test_recovery_preserves_application_and_workflow_revisions_separately(self):
        workflow_sha = "b" * 40
        release.prepare(self.root, TAG, SHA, workflow_sha)
        manifest = release.verify_files(self.root, TAG, SHA)
        self.assertEqual(manifest["git_sha"], SHA)
        self.assertEqual(manifest["workflow_sha"], workflow_sha)
        manifest["workflow_sha"] = "invalid"
        (self.root / "release-manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "full lowercase Git commit"):
            release.verify_files(self.root, TAG, SHA)

    @patch.object(release.subprocess, "run")
    @patch.object(release, "gh")
    @patch.object(release, "download")
    @patch.object(release, "release_info")
    def test_signed_manifest_binds_application_to_approved_recovery_workflow(self, info, download, gh, run):
        workflow_sha = "b" * 40
        release.prepare(self.root, TAG, SHA, workflow_sha)
        info.return_value = {"draft": False, "prerelease": False, "tag_name": TAG,
                             "name": f"XRef {TAG} — Ultra Blazing Fast Reverse Engineering",
                             "html_url": "https://github.com/alex09x/xref/releases/tag/v0.3.0",
                             "assets": [{"name": name} for name in release.asset_names(TAG)]}
        download.side_effect = lambda _tag, name, out: shutil.copy2(self.root / name, out / name)
        release.verify_public(TAG, SHA, self.root / "receipt")
        run.assert_called_once_with(["git", "merge-base", "--is-ancestor", workflow_sha, "origin/main"], check=True)
        self.assertEqual(gh.call_count, 3)
        for call in gh.call_args_list:
            args = call.args
            self.assertEqual(args[args.index("--source-digest") + 1], workflow_sha)
            self.assertEqual(args[args.index("--signer-digest") + 1], workflow_sha)
        self.assertTrue(any(Path(call.args[2]).name == "release-manifest.json" for call in gh.call_args_list))

    @patch.object(release, "verify_public")
    @patch.object(release, "gh")
    @patch.object(release, "release_info", side_effect=[None, {"assets": []}])
    def test_recovery_uses_notes_from_the_pinned_application_tree(self, _info, gh, _verify):
        self._publish_and_check_notes(gh)

    @patch.object(release.time, "sleep")
    @patch.object(release, "verify_public")
    @patch.object(release, "gh")
    @patch.object(release, "release_info", side_effect=[None, None, None, {"assets": []}])
    def test_a_draft_the_listing_shows_late_is_found_again(self, info, gh, _verify, sleep):
        # v0.5.0: the listing did not yet show the draft just created.
        self._publish_and_check_notes(gh)
        self.assertEqual(info.call_count, 4)
        self.assertEqual(sleep.call_count, 2)

    def _publish_and_check_notes(self, gh):
        release.prepare(self.root, TAG, SHA)
        notes = Path("release-source/docs/releases/v0.3.0.md")
        release.publish(self.root, TAG, SHA, notes)
        calls = [call.args for call in gh.call_args_list if "--notes-file" in call.args]
        self.assertEqual(len(calls), 2)
        for args in calls:
            self.assertEqual(args[args.index("--notes-file") + 1], str(notes))

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

    @patch.object(release, "gh")
    def test_existing_draft_is_found_when_published_tag_endpoint_returns_404(self, gh):
        draft = {"tag_name": TAG, "draft": True, "assets": [], "id": 123}
        gh.side_effect = [None, json.dumps([[draft]])]
        self.assertEqual(release.release_info(TAG), draft)
        self.assertIn("--paginate", gh.call_args_list[1].args)

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
    def test_site_accepts_a_versioned_card_variant_and_hashes_the_active_file(self, fetch):
        headers = {"Content-Security-Policy": "default-src 'self'", "Strict-Transport-Security": "max-age=1"}
        base = '{"softwareVersion":"0.3.0"} v0.3.0/xref-v0.3.0-x86_64-unknown-linux-gnu.tar.gz '
        meta = '<meta property="og:image" content="https://xrefcode.com/{}" />'
        html = (base + meta.format("og-v0.3.0-trace.png")).encode()
        fetch.side_effect = [(html, headers), (b"card", {})]
        with patch.object(Path, "read_bytes", return_value=b"card") as read:
            self.assertEqual(channels.check_site(TAG)["channel"], "site")
        self.assertEqual(fetch.call_args_list[1].args[0], "https://xrefcode.com/og-v0.3.0-trace.png")
        self.assertEqual(read.call_count, 1)
        for other in ("og-v0.2.0.png", "og-v0.3.0.png.png", "og-v0.3.0-../x.png"):
            fetch.side_effect = [((base + meta.format(other)).encode(), headers)]
            with self.assertRaisesRegex(ValueError, "does not reference this version"):
                channels.check_site(TAG)

    @patch.object(channels, "fetch")
    def test_site_requires_security_headers_and_tagged_og_bytes(self, fetch):
        html = (b'{"softwareVersion":"0.3.0"} v0.3.0/xref-v0.3.0-x86_64-unknown-linux-gnu.tar.gz '
                b'<meta property="og:image" content="https://xrefcode.com/og-v0.3.0.png" />')
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
