# xref deps

List what a binary says about how it was built: the dependency manifest Rust's
[`cargo-auditable`](https://github.com/rust-secure-code/cargo-auditable)
embeds in `.dep-v0`, or the module list Go embeds in `.go.buildinfo`, together
with the compiler and linker strings from `.comment` and the GNU Build-ID (or
Mach-O `LC_UUID`). Use it to see which crates or modules a stripped release
contains, at which versions, before reading any code.

## Usage

<!-- xref:usage deps -->
```text
xref deps [OPTIONS]
```
<!-- /xref -->

## Arguments and options

<!-- xref:options deps -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--filter <FILTER>` | Case-insensitive substring filter on package or module name. |  |
| `--json` | Emit structured JSON output instead of human-readable text. |  |
<!-- /xref -->

## Examples

### A Rust release built with cargo-auditable

`uv` (Astral's Python package manager) ships its release binaries with the
dependency manifest embedded. The root package, then every runtime and build
dependency with its version:

<!-- xref:run max=12 -->
```console
$ xref -b uv deps
```

```text output
build-id 4f160ca3077054e3dd0cbe63f75e8786671244f9
toolchain GCC: (GNU) 10.2.1 20210130 (Red Hat 10.2.1-11) | GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-44) | rustc version 1.99.0 (b940084d7 2026-09-28) | clang version 23.1.0git | Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)
ecosystem rust (.dep-v0)  root uv 0.13.7  total 567
  uv                                   0.13.7           runtime [root]
  adler2                               2.0.1            runtime
  aes                                  0.8.4            runtime
  aho-corasick                         1.1.4            runtime
  ambient-authority                    0.0.2            runtime
  ambient-id                           0.0.11           runtime
  anstream                             1.0.0            runtime
  anstyle                              1.0.14           runtime
  anstyle-parse                        1.0.0            runtime
```
*Output cut here: lines 1–12 of 571 shown.*

```stderr
xref: load 30.8ms, total 66.6ms
```
<!-- /xref -->

### One crate, as JSON

<!-- xref:run max=30 -->
```console
$ xref -b uv deps --filter tokio --json
```

```json output
{
  "ecosystem": "rust",
  "build_id": "4f160ca3077054e3dd0cbe63f75e8786671244f9",
  "toolchains": [
    "GCC: (GNU) 10.2.1 20210130 (Red Hat 10.2.1-11)",
    "GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-44)",
    "rustc version 1.99.0 (b940084d7 2026-09-28)",
    "clang version 23.1.0git",
    "Linker: LLD 23.1.1 (/checkout/src/llvm-project/llvm 1b9c0d5ff9bbe7634aead059efe6b11a7eeba145)"
  ],
  "root_package": "uv",
  "root_version": "0.13.7",
  "go_version": null,
  "total_packages": 567,
  "packages": [
    {
      "name": "astral-tokio-tar",
      "version": "0.7.0",
      "kind": "runtime",
      "source": "crates.io",
      "root": false,
      "replaced_by": null
    },
    {
      "name": "reqsign-command-execute-tokio",
      "version": "3.0.7",
      "kind": "runtime",
      "source": "crates.io",
      "root": false,
      "replaced_by": null
```
*Output cut here: lines 1–30 of 81 shown.*

```stderr
xref: load 17.7ms, total 54.0ms
```
<!-- /xref -->

### A Go binary

The GitHub CLI `gh` is a static Go binary without unwind tables; `deps` reads
its `.go.buildinfo` module list anyway:

<!-- xref:run max=12 -->
```console
$ xref -b gh deps
```

```text output
build-id e303222785b06a47f8fb46bc6e7f233e7e13eac0
ecosystem go (go1.27.3)  main github.com/cli/cli/v2 v2.103.3  modules 160
  charm.land/bubbles/v2                v2.2.1           module
  charm.land/bubbletea/v2              v2.1.0           module
  charm.land/glamour/v2                v2.0.2-0.20261015065741-010543cac1a0 module
  charm.land/huh/v2                    v2.0.3           module
  charm.land/lipgloss/v2               v2.0.6           module
  dario.cat/mergo                      v1.0.2           module
  github.com/AlecAivazis/survey/v2     v2.3.7           module
  github.com/MakeNowJust/heredoc       v1.0.0           module
  github.com/Masterminds/goutils       v1.1.1           module
  github.com/Masterminds/semver/v3     v3.4.0           module
```
*Output cut here: lines 1–12 of 163 shown.*

```stderr
xref: load 21.8ms, total 33.8ms
```
<!-- /xref -->

### A binary without a manifest

The official ripgrep release is not built with `cargo-auditable` (and has no
Build-ID note); `deps` prints its toolchains and says that there is no
manifest:

<!-- xref:run -->
```console
$ xref -b rg deps
```

```text output
toolchain GCC: (GNU) 9.4.0 | rustc version 1.83.0-nightly (adf8d168a 2024-09-08) | GCC: (GNU) 9.2.0
no embedded dependency manifest (.dep-v0 or .go.buildinfo)
```

```stderr
xref: load 5.9ms, total 12.0ms
```
<!-- /xref -->

## Reading the output

- `build-id` is the GNU Build-ID note (ELF) or `LC_UUID` (Mach-O) in hex.
- `toolchain` lists the distinct `.comment` strings: compilers and linkers of
  the binary and of the objects linked into it, so a Rust binary often names a
  C compiler too.
- `ecosystem rust (.dep-v0)` rows are `name version kind`, where `kind` is
  `runtime` or `build` and `[root]` marks the package the binary was built
  from. `ecosystem go (go1.x)` names the Go toolchain and the main module; its
  rows are `module version module`. With `--json` each Go module also has its
  `h1:` checksum in `source` and, when the module was replaced, the
  replacement in `replaced_by`.
- The same data is in `xref query '{"operation":"dependencies"}'` and in the
  `triage` of `info` (see [`query`](query.md) and [`mcp`](mcp.md)).

## Limits

- Only what the binary embeds: a Rust binary built without `cargo-auditable`
  has no manifest, and the crates it contains are not guessed from strings.
- The `.dep-v0` stream is decompressed to at most 16 MiB from at most 4 MiB;
  a larger or corrupt section is reported, not parsed.
- Without a `.go.buildinfo` section header the Go header is searched in the
  load segments, only at 16-byte aligned addresses and at most 64 times.
- Versions are the strings the build recorded; nothing is checked against a
  registry or an advisory database.

## Provenance

<!-- xref:provenance -->
Recorded with xref 0.5.0 (the remapped release build of commit b00d4a14, made by scripts/package-release.sh before the tag) on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `uv` = uv 0.13.7 (official x86_64-unknown-linux-gnu release, built with cargo-auditable); `gh` = GitHub CLI 2.103.3 (official linux_amd64 release, a static Go binary). Output is unchanged except that whitespace at the end of each line and empty lines at the end of the output are removed; long outputs are cut where marked.
<!-- /xref -->
