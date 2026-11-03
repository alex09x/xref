# Release automation

The release orchestrator is **[`.github/workflows/release.yml`](../.github/workflows/release.yml)**.
`.github/workflows/ci.yml` validates pull requests and `main`, and is reused by the
release workflow. Publication starts on an annotated stable `vX.Y.Z` tag.

The GitHub Release title is:

```text
XRef vX.Y.Z — Ultra Blazing Fast Reverse Engineering
```

Before tagging, merge the version, release notes and translated README updates
through their normal independent review. Preserve English source-pin commits
with fast-forward integration. Preflight checks the exact tagged commit, its
ancestry in `main`, the Cargo version, release notes and translation pins. The
workflow rejects lightweight tags and mismatched versions. Push runs require
the matching tag ref. Recovery dispatches run from reviewed `main` and name an
existing tag explicitly; the tag is never moved.

## crates.io Trusted Publishing

Configure the existing `xref-code` crate at
[crates.io settings](https://crates.io/crates/xref-code/settings):

| Field | Value |
| --- | --- |
| Publisher | GitHub |
| Repository owner | `alex09x` |
| Repository | `xref` |
| Workflow filename | `release.yml` |
| Environment | `crates-io` |

The `publish-crate` job uses `id-token: write` and the official
[`rust-lang/crates-io-auth-action`](https://github.com/rust-lang/crates-io-auth-action),
pinned to an immutable commit. It obtains a temporary publishing token and
revokes it in the action's cleanup step. **Do not add a long-lived
`CARGO_REGISTRY_TOKEN` secret.** Only that step's temporary output is passed to
`cargo publish --locked`. The publisher configuration must exist before the first
tag run; the workflow cannot grant itself publishing access.

## Publication and recovery

1. Required CI and MSRV checks run on the tagged source.
2. Linux x86-64 and macOS arm64 archives are built and checked for target format
   and leaked build paths. Their binaries include the full source commit.
3. The crate is published, then its public archive checksum and embedded Git SHA
   are read back. An already published version is accepted only if it matches
   this exact source commit. Authentication and network errors fail the job.
   A separate job installs that exact public crate into an isolated root and
   checks its executable version.
4. Archive hashes and a source-pinned `release-manifest.json` are attested and
   attached to a draft GitHub Release. The release is made public only after all
   required assets are present. Notes come from `docs/releases/vX.Y.Z.md`.
5. Public archives, checksums, manifest and signed source provenance are verified
   after publication. The signed manifest records the application Git commit
   and the workflow Git commit separately. During recovery, the builder's OIDC
   identity belongs to the newer workflow; its signed manifest binds the
   unchanged application tag to the archive hashes. Verification checks both
   archive and manifest attestations, the builder revision and its ancestry in
   `main`. The deployed site version, install URL, security headers
   and versioned social image bytes are checked separately.
6. The Homebrew readback job waits for the tap's `main` formula to match both
   platform archive URLs and checksums. A missing or outdated formula fails;
   absence of a cross-repository token never becomes a successful skip.

Re-run failed jobs to recover from a transient failure. For a complete repeat,
use **Run workflow**, select branch **main**, set `release_tag` to the existing
tag and turn off `dry_run`. The default manual run validates and builds only.
CI and packaging check out the exact application commit, and release notes come
from that tag's tree. The workflow code may be newer to repair delivery defects.
The named-tag checkout preserves annotations that a default SHA-based checkout
can flatten in the runner's local refs. Published archives are never
overwritten: a repeat verifies their existing hashes and signed source identity.
An unfinished draft with different asset bytes fails explicitly; inspect the
draft before removing any unpublished conflicting asset. Never move a published
tag or replace a published archive.

The Homebrew tap owns formula generation, testing and integration. Its readback
is not a substitute for those checks. The website deploy remains the connected
Cloudflare Workers build on `main`; this workflow verifies the public result.
After public release verification, the release coordinator sends the archive
packet to the EB-1A workspace for Zenodo publication under the existing release
runbook. Zenodo is not a GitHub Actions job and no Zenodo credential is needed
in this repository. Downstream editorial pages retain their own review gates.
An upstream successful job is not evidence that those separate gates completed.

For public channel receipts, inspect the workflow's uploaded JSON artifacts.
No credentials are included in those receipts.
