#!/usr/bin/env python3
# xref — Release preflight and crates.io verification checks
# Copyright (c) 2026 Alexander Panasenko
#
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Release preflight and crates.io verification checks."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

TAG_PATTERN = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
PIN_PATTERN = re.compile(r"<!-- translation-source: ([0-9a-fA-F]{40}) -->")
LOCALES = ("ru", "zh-CN", "es", "pt-BR", "ja", "de", "fr", "ko", "ar")
PACKAGE_NAME = "xref-code"


class PreflightError(Exception):
    """Raised when release preflight checks fail."""


class CrateVerificationError(Exception):
    """Raised when crate verification fails."""


class CrateNotFoundError(Exception):
    """Raised when crate version is not found on crates.io (HTTP 404)."""


def parse_toml(content: str) -> dict:
    """Parse TOML content using tomllib when available, with fallback for Python < 3.11."""
    if tomllib is not None:
        return tomllib.loads(content)

    result: dict = {}
    current_section = None
    packages = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[package]]":
            current_section = "[[package]]"
            packages.append({})
        elif line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            result.setdefault(current_section, {})
        elif "=" in line:
            key, val = [p.strip() for p in line.split("=", 1)]
            val = val.strip("\"'")
            if current_section == "[[package]]" and packages:
                packages[-1][key] = val
            elif current_section:
                result.setdefault(current_section, {})[key] = val
            else:
                result[key] = val
    if packages:
        result["package"] = packages
    return result


def validate_tag(tag: str) -> str:
    if not TAG_PATTERN.match(tag):
        raise ValueError(f"Invalid tag '{tag}': must match strict stable vX.Y.Z")
    return tag


def validate_sha(sha: str) -> str:
    if not SHA_PATTERN.match(sha):
        raise ValueError(f"Invalid commit SHA '{sha}': must be 40-character hex")
    return sha.lower()


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def run_preflight(repo_path: Path, tag: str, sha: str) -> dict[str, str]:
    tag, sha = validate_tag(tag), validate_sha(sha)
    version = tag.removeprefix("v")
    repo = Path(repo_path).resolve()

    # 1. HEAD == SHA
    p = _git(repo, "rev-parse", "HEAD")
    if p.returncode != 0:
        raise PreflightError(f"Failed to get HEAD: {p.stderr.strip()}")
    if p.stdout.strip().lower() != sha:
        raise PreflightError(f"HEAD commit {p.stdout.strip()} does not match expected SHA {sha}")

    # 2. Annotated tag resolves to SHA
    if _git(repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}").returncode != 0:
        raise PreflightError(f"Tag refs/tags/{tag} does not exist")
    obj_type = _git(repo, "cat-file", "-t", f"refs/tags/{tag}").stdout.strip()
    if obj_type != "tag":
        raise PreflightError(f"Tag {tag} is not an annotated tag (object type: {obj_type})")
    tag_sha = _git(repo, "rev-parse", f"refs/tags/{tag}^{{commit}}").stdout.strip().lower()
    if tag_sha != sha:
        raise PreflightError(f"Tag {tag} resolves to {tag_sha}, expected SHA {sha}")

    # 3. SHA ancestor of origin/main
    if _git(repo, "merge-base", "--is-ancestor", sha, "origin/main").returncode != 0:
        raise PreflightError(f"Commit {sha} is not an ancestor of origin/main")

    # 4. Clean git working tree
    p_status = _git(repo, "status", "--porcelain")
    if p_status.returncode != 0 or p_status.stdout.strip():
        raise PreflightError(f"Git working tree is not clean:\n{p_status.stdout}")

    # 5. Cargo.toml and Cargo.lock xref-code version == tag
    cargo_toml = repo / "Cargo.toml"
    if not cargo_toml.is_file():
        raise PreflightError(f"Cargo.toml not found at {cargo_toml}")
    pkg = parse_toml(cargo_toml.read_text(encoding="utf-8")).get("package", {})
    if pkg.get("name") != PACKAGE_NAME or pkg.get("version") != version:
        raise PreflightError(f"Cargo.toml metadata mismatch: expected {PACKAGE_NAME} v{version}")

    cargo_lock = repo / "Cargo.lock"
    if not cargo_lock.is_file():
        raise PreflightError(f"Cargo.lock not found at {cargo_lock}")
    lock_pkgs = [
        p for p in parse_toml(cargo_lock.read_text(encoding="utf-8")).get("package", [])
        if p.get("name") == PACKAGE_NAME and p.get("version") == version
    ]
    if not lock_pkgs:
        raise PreflightError(f"Package '{PACKAGE_NAME}' v'{version}' not found in Cargo.lock")

    # 6. Release note path derived from tag under docs/releases exists
    rel_note = repo / "docs" / "releases" / f"{tag}.md"
    if not rel_note.is_file():
        raise PreflightError(f"Release note missing at {rel_note}")

    # 7. All 9 localized source pin markers real ancestor commits whose README blobs equal current English README
    readme = repo / "README.md"
    if not readme.is_file():
        raise PreflightError(f"README.md not found at {readme}")
    current_readme_bytes = readme.read_bytes()

    for loc in LOCALES:
        loc_readme = repo / "readme" / f"README.{loc}.md"
        if not loc_readme.is_file():
            raise PreflightError(f"Localized README for '{loc}' not found at {loc_readme}")
        m = PIN_PATTERN.search(loc_readme.read_text(encoding="utf-8"))
        if not m:
            raise PreflightError(f"Missing translation-source pin marker in {loc_readme}")
        pin_sha = m.group(1).lower()

        if _git(repo, "merge-base", "--is-ancestor", pin_sha, sha).returncode != 0:
            raise PreflightError(f"Pin commit {pin_sha} in {loc_readme} is not an ancestor of {sha}")
        blob = subprocess.run(
            ["git", "cat-file", "-p", f"{pin_sha}:README.md"],
            cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if blob.returncode != 0 or blob.stdout != current_readme_bytes:
            raise PreflightError(f"README blob at pin {pin_sha} ({loc}) differs from current English README.md")

    result = {"tag": tag, "version": version, "sha": sha}
    print(json.dumps(result))
    return result


def verify_crate_tar(crate_bytes: bytes, expected_name: str, expected_version: str, expected_sha: str) -> dict[str, str]:
    try:
        tf = tarfile.open(fileobj=io.BytesIO(crate_bytes), mode="r:*")
    except Exception as exc:
        raise CrateVerificationError(f"Failed to open .crate tar archive: {exc}")

    vcs_info_bytes = None
    cargo_toml_bytes = None

    with tf:
        for m in tf.getmembers():
            if m.name.startswith(("/", "\\")):
                raise CrateVerificationError(f"Unsafe absolute path in .crate tar: {m.name}")
            parts = os.path.normpath(m.name).replace("\\", "/").split("/")
            if ".." in parts:
                raise CrateVerificationError(f"Unsafe path traversal in .crate tar: {m.name}")
            if m.size > 20 * 1024 * 1024:
                raise CrateVerificationError(f"Member too large in .crate tar: {m.name}")

            filename = parts[-1]
            if filename == ".cargo_vcs_info.json" and len(parts) <= 2:
                f = tf.extractfile(m)
                if f:
                    vcs_info_bytes = f.read()
            elif filename == "Cargo.toml" and len(parts) <= 2:
                f = tf.extractfile(m)
                if f:
                    cargo_toml_bytes = f.read()

    if not vcs_info_bytes:
        raise CrateVerificationError("Missing .cargo_vcs_info.json in .crate archive")
    if not cargo_toml_bytes:
        raise CrateVerificationError("Missing root Cargo.toml in .crate archive")

    try:
        vcs_data = json.loads(vcs_info_bytes.decode("utf-8"))
    except Exception as exc:
        raise CrateVerificationError(f"Invalid JSON in .cargo_vcs_info.json: {exc}")

    git_sha = vcs_data.get("git", {}).get("sha1")
    if not git_sha or git_sha.lower() != expected_sha.lower():
        raise CrateVerificationError(f"git.sha1 mismatch in .cargo_vcs_info.json: expected {expected_sha}, got {git_sha}")

    try:
        toml_data = parse_toml(cargo_toml_bytes.decode("utf-8"))
    except Exception as exc:
        raise CrateVerificationError(f"Invalid TOML in Cargo.toml: {exc}")

    pkg = toml_data.get("package", {})
    if pkg.get("name") != expected_name or pkg.get("version") != expected_version:
        raise CrateVerificationError(f"Metadata mismatch in Cargo.toml: expected {expected_name} v{expected_version}")

    return {"git_sha": git_sha.lower(), "name": pkg["name"], "version": pkg["version"]}


def run_crate(
    tag: str,
    sha: str,
    wait_seconds: int = 0,
    base_url: str = "https://crates.io",
    poll_interval: float = 2.0,
) -> dict[str, str]:
    tag, sha = validate_tag(tag), validate_sha(sha)
    version = tag.removeprefix("v")
    user_agent = f"xref-release-checks/{version} (alex@prod.codes)"
    api_url = f"{base_url.rstrip('/')}/api/v1/crates/{PACKAGE_NAME}/{version}"
    deadline = time.monotonic() + max(0.0, float(wait_seconds))

    version_info = None
    while True:
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": user_agent})
            with urllib.request.urlopen(req) as resp:
                resp_bytes = resp.read()
            version_info = json.loads(resp_bytes.decode("utf-8")).get("version")
            if not isinstance(version_info, dict):
                raise CrateVerificationError("Invalid crates.io response: 'version' object missing")
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                now = time.monotonic()
                if wait_seconds <= 0 or now >= deadline:
                    raise CrateNotFoundError(f"Crate '{PACKAGE_NAME}' v'{version}' not found (HTTP 404)")
                time.sleep(min(poll_interval, max(0.01, deadline - now)))
                continue
            raise CrateVerificationError(f"crates.io HTTP error {exc.code}: {exc.reason}")
        except urllib.error.URLError as exc:
            raise CrateVerificationError(f"crates.io network error: {exc.reason}")
        except Exception as exc:
            if isinstance(exc, (CrateVerificationError, CrateNotFoundError)):
                raise
            raise CrateVerificationError(f"crates.io query error: {exc}")

    if version_info.get("yanked", False):
        raise CrateVerificationError(f"Crate '{PACKAGE_NAME}' version '{version}' is yanked on crates.io")
    if version_info.get("crate") != PACKAGE_NAME or version_info.get("num") != version:
        raise CrateVerificationError(f"API metadata mismatch for {PACKAGE_NAME} v{version}")

    api_checksum = version_info.get("checksum")
    if not api_checksum or not isinstance(api_checksum, str):
        raise CrateVerificationError("Missing or invalid checksum in crates.io API response")

    dl_path = version_info.get("dl_path")
    if dl_path:
        download_url = dl_path if dl_path.startswith(("http://", "https://")) else urllib.parse.urljoin(base_url, dl_path)
    else:
        download_url = f"{base_url.rstrip('/')}/api/v1/crates/{PACKAGE_NAME}/{version}/download"

    try:
        dl_req = urllib.request.Request(download_url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(dl_req) as resp:
            crate_bytes = resp.read()
    except Exception as exc:
        raise CrateVerificationError(f"Failed to download .crate from {download_url}: {exc}")

    computed_sha256 = hashlib.sha256(crate_bytes).hexdigest().lower()
    if computed_sha256 != api_checksum.lower():
        raise CrateVerificationError(f"Crate checksum mismatch: API '{api_checksum}', downloaded '{computed_sha256}'")

    tar_meta = verify_crate_tar(crate_bytes, PACKAGE_NAME, version, sha)
    result = {"sha256": computed_sha256, "git_sha": tar_meta["git_sha"], "version": version}
    print(json.dumps(result))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    p_preflight = subparsers.add_parser("preflight", help="Run release preflight checks")
    p_preflight.add_argument("--tag", required=True, help="Release tag (vX.Y.Z)")
    p_preflight.add_argument("--sha", required=True, help="40-hex commit SHA")
    p_preflight.add_argument("--repo", default=".", help="Path to git repository root")

    p_crate = subparsers.add_parser("crate", help="Verify published crate on crates.io")
    p_crate.add_argument("--tag", required=True, help="Release tag (vX.Y.Z)")
    p_crate.add_argument("--sha", required=True, help="40-hex commit SHA")
    p_crate.add_argument("--wait-seconds", type=int, default=0, help="Polling wait time in seconds")
    p_crate.add_argument("--api-base-url", default="https://crates.io", help=argparse.SUPPRESS)

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    try:
        if args.subcommand == "preflight":
            run_preflight(Path(args.repo), args.tag, args.sha)
        elif args.subcommand == "crate":
            run_crate(args.tag, args.sha, wait_seconds=args.wait_seconds, base_url=args.api_base_url)
        return 0
    except CrateNotFoundError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 3
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
