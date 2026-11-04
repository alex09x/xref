/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Command line. Addresses are static image virtual addresses: `0x` hex or decimal.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xref",
    version,
    about = "Ultra blazing fast cross-references and pseudo-C for x86-64 ELF and Mach-O binaries"
)]
pub struct Cli {
    /// The ELF or supported thin x86-64 Mach-O binary (optional for `xref live`, required for static commands).
    #[arg(short, long, env = "XREF_BIN")]
    pub bin: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run a versioned structured query supplied as a JSON object.
    Query { request: String },
    /// Symbolize bounded offline addresses, perf-script callchains, or folded stacks.
    Symbolize(crate::trace_frontend::cli::SymbolizeArgs),
    /// Import observed stack-adjacency evidence for opt-in graph queries.
    Edges {
        #[command(subcommand)]
        command: crate::trace_frontend::cli::EdgeCommand,
    },
    /// Serve read-only MCP over stdio for this one immutable binary snapshot (or opt-in live PID inspection).
    Mcp {
        /// Explicitly enable the PID-bound `xref_live` MCP tool for this single verified Linux process.
        #[arg(long, value_name = "PID")]
        allow_live_pid: Option<u32>,
    },
    /// Functions, code size, data pointers, imports and panic locations.
    Stats,
    /// Function symbols whose name contains a pattern (non-stripped binaries).
    Sym { pattern: String },
    /// The function (exact `.eh_frame` range) containing each address.
    Func {
        #[arg(required = true, value_parser = parse_number)]
        addrs: Vec<u64>,
    },
    /// Code and data slots naming addresses (`0x...`) or text (anything else).
    Refs {
        #[arg(required = true)]
        targets: Vec<String>,
        /// Also accept references this many bytes before a text (rustc format pieces start with a length byte).
        #[arg(long, default_value_t = 1)]
        back: u64,
        /// Search for strings built inline from immediate stores (`movabs` / `mov [mem], imm`).
        #[arg(long)]
        inline: bool,
    },
    /// Strings built inline from immediate stores (`movabs` / `mov [mem], imm`).
    Istr {
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Instructions with an immediate operand.
    Imm {
        #[arg(value_parser = parse_number)]
        value: u64,
        /// Only `mov [memory], imm`.
        #[arg(long)]
        store: bool,
        /// Only `cmp`.
        #[arg(long)]
        cmp: bool,
        /// Only inside the function containing this address.
        #[arg(long = "in", value_parser = parse_number)]
        within: Option<u64>,
    },
    /// Instructions reading or writing struct fields: non-stack memory operands with these displacements.
    Disp {
        #[arg(required = true, value_parser = parse_number)]
        values: Vec<u64>,
        /// Only instructions writing the memory operand.
        #[arg(long)]
        write: bool,
        /// Only `lea` instructions taking the field's address.
        #[arg(long)]
        lea: bool,
        /// Functions accessing all of the given displacements (an intersection), with per-function counts.
        #[arg(long)]
        all: bool,
        /// Only accesses whose base or index register was computed with this array element stride.
        #[arg(long, value_parser = parse_number)]
        stride: Option<u64>,
        /// Include stack displacements and fields relative to explicitly address-taken stack buffers.
        #[arg(long)]
        stack: bool,
        /// Only inside the function containing this address.
        #[arg(long = "in", value_parser = parse_number)]
        within: Option<u64>,
    },
    /// Direct calls and jumps to an address, and code taking its address or loading a slot holding it.
    Callers {
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// Explicit observed-edge store tied to this binary; sample counts are not call counts.
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Calls and tail jumps of the function containing an address, in code order.
    Calls {
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
    /// Constant and symbolic arguments at every call site of a function (rdi..r9 and stack0..N).
    Args {
        addr: String,
        /// Maximum number of stack argument slots to inspect.
        #[arg(long, default_value_t = 4)]
        max: usize,
    },
    /// Functions satisfying multiple predicates in one parallel pass.
    Find {
        /// Function calls or tail-jumps to ADDR (repeatable).
        #[arg(long)]
        calls: Vec<String>,
        /// Function references string or hex address (repeatable).
        #[arg(long)]
        refs: Vec<String>,
        /// Function uses immediate constant N (repeatable).
        #[arg(long, value_parser = parse_number)]
        imm: Vec<u64>,
        /// Only `mov [mem], imm` stores for `--imm`.
        #[arg(long)]
        store: bool,
        /// Only `cmp` instructions for `--imm`.
        #[arg(long)]
        cmp: bool,
        /// Function accesses struct field at displacement OFF (repeatable).
        #[arg(long, value_parser = parse_number)]
        disp: Vec<u64>,
        /// Only memory writes for `--disp`.
        #[arg(long)]
        write: bool,
        /// Only `lea` address-of uses for `--disp`.
        #[arg(long)]
        lea: bool,
        /// Function references panic Location matching PATTERN (repeatable).
        #[arg(long)]
        src: Vec<String>,
        /// Function byte size range (`MIN..MAX`, `MIN..`, `..MAX`, or `EXACT`).
        #[arg(long)]
        size: Option<String>,
        /// Minimum number of predicates to satisfy (default: all); ranks by match count.
        #[arg(long)]
        any: Option<usize>,
        /// Bytes before each `--refs` string to include in reachability window.
        #[arg(long, default_value_t = 16, value_parser = parse_number)]
        back: u64,
        /// Instruction mnemonic with optional Intel operand glob (repeatable).
        #[arg(long)]
        insn: Vec<String>,
        /// Instruction class; currently `float` (repeatable).
        #[arg(long)]
        class: Vec<String>,
    },
    /// Shortest call chains from function FROM to function TO over direct calls, tail jumps and pointer slots.
    Path {
        from: String,
        to: String,
        /// Maximum call-chain depth (hops).
        #[arg(long, default_value_t = 8)]
        depth: usize,
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Indented caller or callee tree of a function, with ranges and first panic locations.
    Tree {
        addr: String,
        /// Show callers instead of callees.
        #[arg(long)]
        callers: bool,
        /// Show callees (default).
        #[arg(long)]
        callees: bool,
        /// Maximum tree depth.
        #[arg(long, default_value_t = 3)]
        depth: usize,
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Counterpart of each function in another build of the binary, scored by shared locations, strings, immediates and call graph.
    #[command(visible_alias = "diff")]
    Match(crate::matching_cli::MatchArgs),
    /// Annotated disassembly of the function containing an address.
    Asm {
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// First address to print.
        #[arg(long, value_parser = parse_number)]
        from: Option<u64>,
        /// End address (exclusive).
        #[arg(long, value_parser = parse_number)]
        to: Option<u64>,
    },
    /// Pseudo-C decompilation of the functions containing each address.
    #[command(visible_alias = "decomp")]
    C {
        #[arg(required = true, value_parser = parse_number)]
        addrs: Vec<u64>,
        /// First address to print.
        #[arg(long, value_parser = parse_number)]
        from: Option<u64>,
        /// End address (exclusive).
        #[arg(long, value_parser = parse_number)]
        to: Option<u64>,
        /// Write each decompiled function to `<OUT>/<start>.c` in parallel and print path, size and elapsed time.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Rewrite raw pointer offsets as inferred `->f_<off>` field hints using layout recovery.
        #[arg(long)]
        fields: bool,
        /// Keep residual labels and gotos instead of introducing skip flags; retain structured loops and branches.
        #[arg(long = "goto")]
        keep_gotos: bool,
    },
    /// Backward program slice: minimal pseudo-C statements and branches reaching a target address or text.
    Slice {
        addr: String,
        /// Target hex address, call name, field offset, or string substring inside the function.
        #[arg(long)]
        to: String,
        /// Rewrite raw pointer offsets as inferred `->f_<off>` field hints before slicing.
        #[arg(long)]
        fields: bool,
        /// Keep residual labels and gotos in the sliced pseudo-C.
        #[arg(long = "goto")]
        keep_gotos: bool,
    },
    /// Normalized cross-build pseudo-C diff between counterpart functions in two binaries.
    #[command(name = "diff-c")]
    DiffC {
        /// The other binary build to compare against.
        #[arg(long)]
        other: PathBuf,
        #[arg(required = true)]
        addrs: Vec<String>,
        /// Explicit counterpart address/symbol in `--other` (auto-matched when omitted).
        #[arg(long)]
        target: Option<String>,
        /// Rewrite raw pointer offsets as inferred `->f_<off>` field hints before diffing.
        #[arg(long)]
        fields: bool,
    },
    /// Parallel modular pseudo-C dump grouped by recovered Rust source paths (`<OUT>/crate/src/mod.c`).
    Dump {
        /// Output directory for grouped `.c` module files.
        #[arg(long)]
        out: PathBuf,
        /// Optional substring filter on source path or symbol name (e.g. `src/loops.rs`).
        #[arg(long)]
        src: Option<String>,
        /// Rewrite raw pointer offsets as inferred `->f_<off>` field hints.
        #[arg(long)]
        fields: bool,
        /// Keep residual labels and gotos in every dumped function.
        #[arg(long = "goto")]
        keep_gotos: bool,
    },
    /// Enum variant whose `Display`/`match` arm names a text: the jump-table index of the referencing arm.
    Error {
        text: String,
        #[arg(long, default_value_t = 1)]
        back: u64,
    },
    /// Jump-table arms of the function containing an address for enum variant indices, with the texts they name.
    Variant {
        #[arg(value_parser = parse_number)]
        addr: u64,
        #[arg(required = true, value_parser = parse_number)]
        indices: Vec<u64>,
    },
    /// Jump-table indices whose arm holds each address (closest preceding arm of every table, best first).
    Arm {
        #[arg(required = true, value_parser = parse_number)]
        addrs: Vec<u64>,
    },
    /// Rust source locations (panic `Location`s) the function containing an address passes.
    Src {
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
    /// Functions passing source locations whose file contains a pattern (and optionally at one line).
    Where {
        pattern: String,
        #[arg(long)]
        line: Option<u32>,
    },
    /// Distinct source files of the panic locations (optionally containing a pattern), with counts.
    Files { pattern: Option<String> },
    /// Reconstructed struct field layout accessed via an argument register (and optionally callees receiving it).
    Layout {
        addr: String,
        /// Parameter or general-purpose register holding the struct pointer.
        #[arg(long, default_value = "rdi")]
        reg: String,
        /// Follow direct/slot calls one hop where the struct pointer is forwarded.
        #[arg(long)]
        callees: bool,
    },
    /// Candidate Serde field layouts backed by key-string and memory-access instruction witnesses.
    Field {
        /// Single serialized key to query.
        #[arg(required_unless_present = "keys", conflicts_with = "keys")]
        name: Option<String>,
        /// Exact comma-separated set of sibling serialized keys (`--keys c,m,e`).
        #[arg(long, value_name = "KEYS")]
        keys: Option<String>,
        /// Only functions containing this address or symbol.
        #[arg(long)]
        within: Option<String>,
        /// Emit the structured report as JSON.
        #[arg(long)]
        json: bool,
        /// Require this many distinct serialized offsets on the same input root in an accessor.
        #[arg(long, default_value_t = 2)]
        min_offsets: usize,
        /// Accept a key-set candidate matching at least N requested keys; defaults to the full set.
        #[arg(long)]
        min_keys: Option<usize>,
        /// Maximum sibling helper functions selected into the discovery context (1..=8192).
        #[arg(long, default_value_t = crate::serde_fields::DEFAULT_KEY_FUNCTION_BUDGET)]
        max_functions: usize,
        /// Maximum decoded instructions per function for key/value analysis (1..=16384).
        #[arg(long, default_value_t = crate::serde_fields::DEFAULT_KEY_INSTRUCTION_BUDGET)]
        max_instructions: usize,
        /// Show accessor instructions that may write the queried field.
        #[arg(long)]
        write: bool,
        /// Maximum accessor rows (1..=128).
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// Skip the global accessor search while inspecting layout evidence.
        #[arg(long)]
        layout_only: bool,
    },
    /// Inspect a live Linux process via procfs (maps, address translation, and xref memory scan).
    Live(crate::live::cli::LiveCommand),
}

pub fn parse_number(text: &str) -> Result<u64, String> {
    let parsed = text.strip_prefix("0x").map_or_else(|| text.parse::<u64>(), |hex| u64::from_str_radix(hex, 16));
    parsed.map_err(|error| format!("{text}: {error}"))
}

/// A `0x` hex address argument; anything else is text.
pub fn hex_address(text: &str) -> Option<u64> {
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{hex_address, parse_number};

    #[test]
    fn numbers_are_hex_with_a_prefix_and_decimal_without() {
        assert_eq!(parse_number("0x194"), Ok(404));
        assert_eq!(parse_number("404"), Ok(404));
        assert!(parse_number("0xzz").is_err());
        assert_eq!(hex_address("0x439041"), Some(0x43_9041));
        assert_eq!(hex_address("some text"), None);
        assert_eq!(hex_address("404"), None);
    }
}
