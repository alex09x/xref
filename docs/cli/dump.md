# xref dump

Parallel modular pseudo-C dump grouped by recovered Rust source paths (`<OUT>/crate/src/mod.c`).

Groups stripped functions by embedded Rust panic file paths and writes modular .c files in parallel. Stdout and generated file preview are shown separately below.

## Usage

<!-- xref:usage dump -->
```text
xref dump [OPTIONS] --out <OUT>
```
<!-- /xref -->

## Arguments and options

<!-- xref:options dump -->
**Options**

| Option | Description | Default |
| --- | --- | --- |
| `--out <OUT>` | Output directory for grouped `.c` module files. |  |
| `--src <SRC>` | Optional substring filter on source path or symbol name (e.g. `src/loops.rs`). |  |
| `--fields` | Rewrite raw pointer offsets as inferred `->f_<off>` field hints. |  |
| `--goto` | Keep residual labels and gotos in every dumped function. |  |
<!-- /xref -->

## Examples

All examples were recorded on public binaries; see [Provenance](#provenance).

### Dump --out out-loops --src src/loops.rs

Exports the 4 functions attributed to src/loops.rs into out-loops/src/loops.c.

<!-- xref:run max=40 -->
```console
$ xref -b xref.stripped dump --out out-loops --src src/loops.rs
```

```text output
dumped 4 functions into 1 files (12738 bytes) in out-loops (5.1ms)
```

```stderr
xref: load 529.7µs, total 5.7ms
```
<!-- /xref -->

## Reading the output

- stdout is one summary line: how many functions went into how many files, the bytes written, the output directory and the time.
- The files are `<OUT>/<crate>/src/<module>.c`, one per recovered Rust source path; each holds the pseudo-C of the functions whose panic locations point to that file.

## Limits

- Functions are grouped by the source paths of their panic locations; functions without any panic location are not exported by `--src`.

## Provenance

<!-- xref:provenance -->
Recorded with a development build of xref after 0.4.0 on Linux x86-64, on `rg` = ripgrep 14.1.1 (official stripped release); `xref.stripped` = a stripped xref build (the binary of the home-page examples); `xref-v0.0.2.stripped` = stripped xref 0.0.2; `xref-0.4.0` = the xref 0.4.0 Linux release binary (not stripped). Output is unchanged; long outputs are cut where marked.
<!-- /xref -->
