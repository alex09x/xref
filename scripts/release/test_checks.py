#!/usr/bin/env python3
# xref — Unit tests for release preflight and crates.io checks
# Copyright (c) 2026 Alexander Panasenko
#
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Deterministic offline unit tests for release preflight and crate verification."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

# Ensure scripts.release and local directory are importable
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from scripts.release import checks
except ImportError:
    import checks


def build_test_crate(
    pkg_name: str = "xref-code",
    version: str = "0.3.0",
    git_sha: str = "e4d36912d8fc74989beeb909d854e9020a24b854",
    custom_members: dict[str, bytes] | None = None,
) -> bytes:
    buf = io.BytesIO()
    prefix = f"{pkg_name}-{version}"
    vcs_info = json.dumps({"git": {"sha1": git_sha}, "path_in_vcs": ""}).encode("utf-8")
    cargo_toml = f'[package]\nname = "{pkg_name}"\nversion = "{version}"\n'.encode("utf-8")

    members = {
        f"{prefix}/.cargo_vcs_info.json": vcs_info,
        f"{prefix}/Cargo.toml": cargo_toml,
    }
    if custom_members:
        members.update(custom_members)

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class TestValidation(unittest.TestCase):
    def test_valid_tags(self):
        for tag in ("v0.1.0", "v0.3.0", "v1.0.0", "v10.20.300"):
            self.assertEqual(checks.validate_tag(tag), tag)

    def test_malformed_tags(self):
        invalid = (
            "0.1.0", "v01.0.0", "v1.02.0", "v0.3", "v1", "v1.0.0.0",
            "v1.0.0-rc1", "v1.0.0+build", "vX.Y.Z", "v-1.0.0", "",
        )
        for tag in invalid:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                checks.validate_tag(tag)

    def test_valid_shas(self):
        sha = "e4d36912d8fc74989beeb909d854e9020a24b854"
        self.assertEqual(checks.validate_sha(sha), sha)
        self.assertEqual(checks.validate_sha(sha.upper()), sha)

    def test_malformed_shas(self):
        invalid = (
            "e4d3691", "e4d36912d8fc74989beeb909d854e9020a24b85",
            "e4d36912d8fc74989beeb909d854e9020a24b8544",
            "g4d36912d8fc74989beeb909d854e9020a24b854", "", "   ",
        )
        for sha in invalid:
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                checks.validate_sha(sha)


class TestPreflightGitFixture(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Alexander Panasenko")
        self._git("config", "user.email", "alex@prod.codes")
        self._git("config", "commit.gpgsign", "false")

        (self.repo / "Cargo.toml").write_text(
            '[package]\nname = "xref-code"\nversion = "0.3.0"\n', encoding="utf-8"
        )
        (self.repo / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "xref-code"\nversion = "0.3.0"\n',
            encoding="utf-8",
        )
        (self.repo / "README.md").write_text("Canonical English README\n", encoding="utf-8")
        docs_rel = self.repo / "docs" / "releases"
        docs_rel.mkdir(parents=True)
        (docs_rel / "v0.3.0.md").write_text("# Release v0.3.0\n", encoding="utf-8")

        self._git("add", ".")
        self._git("commit", "-m", "chore: initial commit")
        self.commit1 = self._git("rev-parse", "HEAD").strip()

        readme_dir = self.repo / "readme"
        readme_dir.mkdir(parents=True)
        for loc in checks.LOCALES:
            (readme_dir / f"README.{loc}.md").write_text(
                f"<!-- translation-source: {self.commit1} -->\nLocalized {loc}\n",
                encoding="utf-8",
            )

        self._git("add", ".")
        self._git("commit", "-m", "docs: add localized readmes")
        self.head_sha = self._git("rev-parse", "HEAD").strip()
        self._git("update-ref", "refs/remotes/origin/main", self.head_sha)
        self._git("tag", "-a", "v0.3.0", "-m", "Release v0.3.0")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return proc.stdout

    def _retag_head(self, tag="v0.3.0"):
        new_head = self._git("rev-parse", "HEAD").strip()
        self._git("update-ref", "refs/remotes/origin/main", new_head)
        self._git("tag", "-d", tag)
        self._git("tag", "-a", tag, "-m", "tag", new_head)
        return new_head

    def test_preflight_success(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            res = checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertEqual(res, {"tag": "v0.3.0", "version": "0.3.0", "sha": self.head_sha})
        self.assertEqual(json.loads(out.getvalue()), res)

    def test_preflight_head_mismatch(self):
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.commit1)
        self.assertIn("does not match expected SHA", str(ctx.exception))

    def test_preflight_tag_missing(self):
        self._git("tag", "-d", "v0.3.0")
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertIn("does not exist", str(ctx.exception))

    def test_preflight_tag_lightweight_rejected(self):
        self._git("tag", "-d", "v0.3.0")
        self._git("tag", "v0.3.0")
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertIn("not an annotated tag", str(ctx.exception))

    def test_preflight_tag_resolves_wrong_sha(self):
        self._git("tag", "-d", "v0.3.0")
        self._git("tag", "-a", "v0.3.0", "-m", "Tagging commit1", self.commit1)
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertIn("resolves to", str(ctx.exception))

    def test_preflight_sha_not_ancestor_of_origin_main(self):
        self._git("update-ref", "refs/remotes/origin/main", self.commit1)
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertIn("not an ancestor of origin/main", str(ctx.exception))

    def test_preflight_dirty_git(self):
        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", self.head_sha)
        self.assertIn("not clean", str(ctx.exception))

    def test_preflight_cargo_toml_version_mismatch(self):
        (self.repo / "Cargo.toml").write_text('[package]\nname = "xref-code"\nversion = "0.2.0"\n')
        self._git("commit", "-am", "bump to 0.2.0")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("Cargo.toml metadata mismatch", str(ctx.exception))

    def test_preflight_cargo_lock_version_mismatch(self):
        (self.repo / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "xref-code"\nversion = "0.2.0"\n')
        self._git("commit", "-am", "bump lock to 0.2.0")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("not found in Cargo.lock", str(ctx.exception))

    def test_preflight_release_notes_missing(self):
        (self.repo / "docs" / "releases" / "v0.3.0.md").unlink()
        self._git("commit", "-am", "remove release note")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("Release note missing", str(ctx.exception))

    def test_preflight_pin_marker_missing(self):
        (self.repo / "readme" / "README.ja.md").write_text("No pin marker\n", encoding="utf-8")
        self._git("commit", "-am", "remove pin marker")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("Missing translation-source pin marker", str(ctx.exception))

    def test_preflight_pin_not_ancestor(self):
        fake = "0123456789abcdef0123456789abcdef01234567"
        (self.repo / "readme" / "README.ja.md").write_text(f"<!-- translation-source: {fake} -->\n", encoding="utf-8")
        self._git("commit", "-am", "fake pin")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("not an ancestor", str(ctx.exception))

    def test_preflight_pin_readme_blob_mismatch(self):
        (self.repo / "README.md").write_text("Modified English README\n", encoding="utf-8")
        self._git("commit", "-am", "modify english readme")
        new_head = self._retag_head()
        with self.assertRaises(checks.PreflightError) as ctx:
            checks.run_preflight(self.repo, "v0.3.0", new_head)
        self.assertIn("differs from current English README.md", str(ctx.exception))


class TestCrateVerificationMocked(unittest.TestCase):
    def setUp(self):
        self.tag = "v0.3.0"
        self.sha = "e4d36912d8fc74989beeb909d854e9020a24b854"
        self.crate_bytes = build_test_crate(git_sha=self.sha)
        self.checksum = hashlib.sha256(self.crate_bytes).hexdigest()

    def _mock_response(self, data: bytes) -> MagicMock:
        cm = MagicMock()
        cm.read.return_value = data
        cm.__enter__.return_value = cm
        return cm

    def test_crate_success(self):
        api_data = json.dumps({
            "version": {
                "crate": "xref-code",
                "num": "0.3.0",
                "yanked": False,
                "checksum": self.checksum,
                "dl_path": "/api/v1/crates/xref-code/0.3.0/download",
            }
        }).encode("utf-8")

        with patch("urllib.request.urlopen", side_effect=[self._mock_response(api_data), self._mock_response(self.crate_bytes)]) as mock_url:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                res = checks.run_crate(self.tag, self.sha, wait_seconds=0)

            self.assertEqual(res, {"sha256": self.checksum, "git_sha": self.sha, "version": "0.3.0"})
            self.assertEqual(json.loads(out.getvalue()), res)
            req1 = mock_url.call_args_list[0][0][0]
            self.assertIn("User-agent", {k.capitalize(): v for k, v in req1.headers.items()})

    def test_crate_404_wait_zero_exits_3(self):
        err = urllib.error.HTTPError("https://crates.io", 404, "Not Found", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(checks.CrateNotFoundError):
                checks.run_crate(self.tag, self.sha, wait_seconds=0)

            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = checks.main(["crate", "--tag", self.tag, "--sha", self.sha, "--wait-seconds", "0"])
            self.assertEqual(exit_code, 3)

    def test_crate_404_polling_success(self):
        api_data = json.dumps({
            "version": {
                "crate": "xref-code", "num": "0.3.0", "yanked": False,
                "checksum": self.checksum, "dl_path": "/download",
            }
        }).encode("utf-8")
        err = urllib.error.HTTPError("https://crates.io", 404, "Not Found", {}, None)

        with patch("urllib.request.urlopen", side_effect=[err, self._mock_response(api_data), self._mock_response(self.crate_bytes)]):
            with patch("time.sleep", return_value=None):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    res = checks.run_crate(self.tag, self.sha, wait_seconds=5, poll_interval=0.01)
                self.assertEqual(res["version"], "0.3.0")

    def test_crate_404_polling_timeout_exits_3(self):
        err = urllib.error.HTTPError("https://crates.io", 404, "Not Found", {}, None)
        with patch("urllib.request.urlopen", side_effect=err):
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = checks.main(["crate", "--tag", self.tag, "--sha", self.sha, "--wait-seconds", "0"])
            self.assertEqual(exit_code, 3)

    def _assert_failclosed(self, make_side_effect, match_error=None):
        with patch("urllib.request.urlopen", side_effect=make_side_effect()):
            with self.assertRaises(checks.CrateVerificationError) as ctx:
                checks.run_crate(self.tag, self.sha, wait_seconds=0)
            if match_error:
                self.assertIn(match_error.lower(), str(ctx.exception).lower())
        with patch("urllib.request.urlopen", side_effect=make_side_effect()):
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = checks.main(["crate", "--tag", self.tag, "--sha", self.sha])
            self.assertEqual(exit_code, 1)

    def test_crate_failclosed_http_500(self):
        self._assert_failclosed(lambda: urllib.error.HTTPError("https://crates.io", 500, "Server Error", {}, None))

    def test_crate_failclosed_http_403(self):
        self._assert_failclosed(lambda: urllib.error.HTTPError("https://crates.io", 403, "Forbidden", {}, None))

    def test_crate_failclosed_network_error(self):
        self._assert_failclosed(lambda: urllib.error.URLError("Connection refused"))

    def test_crate_failclosed_yanked(self):
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": True, "checksum": self.checksum}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api)], "yanked")

    def test_crate_failclosed_checksum_mismatch(self):
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": False, "checksum": "0" * 64, "dl_path": "/dl"}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api), self._mock_response(self.crate_bytes)], "checksum mismatch")

    def test_crate_failclosed_git_sha_mismatch(self):
        bad_crate = build_test_crate(git_sha="1" * 40)
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": False, "checksum": hashlib.sha256(bad_crate).hexdigest(), "dl_path": "/dl"}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api), self._mock_response(bad_crate)], "git.sha1 mismatch")

    def test_crate_failclosed_package_name_or_version_mismatch(self):
        bad_crate = build_test_crate(pkg_name="other-pkg")
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": False, "checksum": hashlib.sha256(bad_crate).hexdigest(), "dl_path": "/dl"}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api), self._mock_response(bad_crate)], "mismatch")

    def test_crate_failclosed_unsafe_tar_traversal(self):
        bad = build_test_crate(custom_members={"xref-code-0.3.0/../../evil.txt": b"evil"})
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": False, "checksum": hashlib.sha256(bad).hexdigest(), "dl_path": "/dl"}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api), self._mock_response(bad)], "unsafe path traversal")

    def test_crate_failclosed_unsafe_tar_absolute(self):
        bad = build_test_crate(custom_members={"/etc/passwd": b"evil"})
        api = json.dumps({"version": {"crate": "xref-code", "num": "0.3.0", "yanked": False, "checksum": hashlib.sha256(bad).hexdigest(), "dl_path": "/dl"}}).encode()
        self._assert_failclosed(lambda: [self._mock_response(api), self._mock_response(bad)], "unsafe absolute path")


class TestCLI(unittest.TestCase):
    def test_cli_malformed_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(checks.main(["preflight", "--tag", "0.3.0", "--sha", "abc"]), 1)
            self.assertEqual(checks.main(["crate", "--tag", "0.3.0", "--sha", "abc"]), 1)


if __name__ == "__main__":
    unittest.main()
