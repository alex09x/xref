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
<!-- /xref -->

### One crate, as JSON

<!-- xref:run max=30 -->
```console
$ xref -b uv deps --filter tokio --json
```
<!-- /xref -->

### A Go binary

The GitHub CLI `gh` is a static Go binary without unwind tables; `deps` reads
its `.go.buildinfo` module list anyway:

<!-- xref:run max=12 -->
```console
$ xref -b gh deps
```
<!-- /xref -->

### A binary without a manifest

The official ripgrep release is not built with `cargo-auditable`; `deps` still
prints the Build-ID and toolchains and says that there is no manifest:

<!-- xref:run -->
```console
$ xref -b rg deps
```
<!-- /xref -->

## Reading the output

- `build-id` is the GNU Build-ID note (ELF) or `LC_UUID` (Mach-O) in hex.
- `toolchain` lists the distinct `.comment` strings: compilers and linkers of
  the binary and of the objects linked into it, so a Rust binary often names a
  C compiler too.
- `ecosystem rust (.dep-v0)` rows are `name version kind`, where `kind` is
  `runtime` or `build` and `[root]` marks the package the binary was built
  from. `ecosystem go (.go.buildinfo)` rows are `module version` with the
  `h1:` checksum, a `=>` replacement when the module was replaced, and the
  `build` settings (`-buildmode`, `CGO_ENABLED`, VCS revision) at the end.
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
<!-- /xref -->
