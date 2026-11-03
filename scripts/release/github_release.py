#!/usr/bin/env python3
# XRef — release archive publication and readback
# Copyright (c) 2026 Alexander Panasenko
# Contact: alex@prod.codes
# Author: https://prod.codes/about/
# Project: https://github.com/alex09x/xref
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Publish missing assets, never replace a previously uploaded asset."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = "alex09x/xref"
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")


def gh(*args, missing_ok=False):
    result = subprocess.run(["gh", *args], text=True, capture_output=True)
    if result.returncode:
        if missing_ok and "(HTTP 404)" in result.stderr:
            return None
        raise RuntimeError(f"gh {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def identity(tag, sha):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag):
        raise ValueError("expected a stable vX.Y.Z tag")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("expected the full lowercase Git commit SHA")


def archive_names(tag):
    return [f"xref-{tag}-{target}.tar.gz" for target in TARGETS]


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def prepare(root, tag, sha):
    identity(tag, sha)
    files = []
    for name in archive_names(tag):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing regular archive: {name}")
        checksum = digest(path)
        expected = f"{checksum}  {name}\n"
        if (root / f"{name}.sha256").read_text() != expected:
            raise ValueError(f"archive sidecar mismatch: {name}")
        files.append({"name": name, "sha256": checksum, "size": path.stat().st_size})
    (root / "SHA256SUMS").write_text("".join(f"{f['sha256']}  {f['name']}\n" for f in files))
    manifest = {"schema_version": 1, "tag": tag, "version": tag[1:], "git_sha": sha, "archives": files}
    (root / "release-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def release_info(tag, missing_ok=False):
    raw = gh("api", f"repos/{REPO}/releases/tags/{tag}", missing_ok=missing_ok)
    return json.loads(raw) if raw is not None else None


def download(tag, name, directory):
    gh("release", "download", tag, "--repo", REPO, "--pattern", name, "--dir", str(directory))


def verify_files(root, tag, sha):
    """Validate downloaded files against their source-pinned manifest."""
    identity(tag, sha)
    manifest = json.loads((root / "release-manifest.json").read_text())
    if (manifest.get("schema_version"), manifest.get("tag"), manifest.get("version"), manifest.get("git_sha")) != (1, tag, tag[1:], sha):
        raise ValueError("published release manifest has a different source identity")
    entries = manifest.get("archives", [])
    if len(entries) != 2 or {f.get("name") for f in entries} != set(archive_names(tag)):
        raise ValueError("published manifest has an unexpected archive set")
    sums = []
    for entry in sorted(entries, key=lambda x: x["name"]):
        path = root / entry["name"]
        checksum = digest(path)
        if checksum != entry["sha256"] or path.stat().st_size != entry["size"]:
            raise ValueError(f"published archive mismatch: {path.name}")
        line = f"{checksum}  {path.name}\n"
        if (root / f"{path.name}.sha256").read_text() != line:
            raise ValueError(f"published sidecar mismatch: {path.name}")
        sums.append(line)
    if (root / "SHA256SUMS").read_text() != "".join(sums):
        raise ValueError("published SHA256SUMS mismatch")
    return manifest


def asset_names(tag):
    names = archive_names(tag)
    return [*names, *(f"{name}.sha256" for name in names), "SHA256SUMS", "release-manifest.json"]


def verify_public(tag, sha, output):
    info = release_info(tag)
    title = f"XRef {tag} — Ultra Blazing Fast Reverse Engineering"
    if info["draft"] or info["prerelease"] or info["tag_name"] != tag or info["name"] != title:
        raise ValueError("release is not the expected public stable release")
    names = {asset["name"] for asset in info["assets"]}
    if not set(asset_names(tag)) <= names:
        raise ValueError("public release is missing required assets")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        for name in asset_names(tag):
            download(tag, name, root)
        manifest = verify_files(root, tag, sha)
        # Check the signed archive provenance, including source revision and workflow.
        for name in archive_names(tag):
            gh("attestation", "verify", str(root / name), "--repo", REPO,
               "--signer-workflow", f"{REPO}/.github/workflows/release.yml",
               "--source-digest", sha, "--deny-self-hosted-runners")
    output.mkdir(parents=True, exist_ok=True)
    (output / "github-receipt.json").write_text(json.dumps({"release_url": info["html_url"], **manifest}, indent=2) + "\n")
    return info


def publish(root, tag, sha):
    identity(tag, sha)
    verify_files(root, tag, sha)
    info = release_info(tag, missing_ok=True)
    if info is not None and not info["draft"]:
        # Rebuilt tarballs can differ in timestamps. Verify the immutable public
        # artifacts and their attested source instead of replacing them on retry.
        return verify_public(tag, sha, root)
    if info is None:
        gh("release", "create", tag, "--repo", REPO, "--verify-tag", "--draft",
           "--title", f"XRef {tag} — Ultra Blazing Fast Reverse Engineering",
           "--notes-file", f"docs/releases/{tag}.md")
        info = release_info(tag)
    existing = {asset["name"] for asset in info["assets"]}
    with tempfile.TemporaryDirectory() as temp:
        for name in asset_names(tag):
            if name in existing:
                download(tag, name, Path(temp))
                if digest(Path(temp) / name) != digest(root / name):
                    raise ValueError(f"draft asset already exists with different bytes: {name}; no asset was overwritten")
            else:
                gh("release", "upload", tag, str(root / name), "--repo", REPO)
    gh("release", "edit", tag, "--repo", REPO, "--draft=false",
       "--title", f"XRef {tag} — Ultra Blazing Fast Reverse Engineering",
       "--notes-file", f"docs/releases/{tag}.md")
    return verify_public(tag, sha, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "publish", "verify"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_REPOSITORY", REPO) != REPO:
        parser.error("publication is restricted to alex09x/xref")
    try:
        if args.command == "prepare":
            prepare(args.artifacts, args.tag, args.sha)
        elif args.command == "publish":
            publish(args.artifacts, args.tag, args.sha)
        else:
            verify_public(args.tag, args.sha, args.artifacts)
    except (ValueError, RuntimeError, OSError, KeyError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
