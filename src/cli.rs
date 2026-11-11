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
    /// Analyze a recorded sampling profile.
    Profile {
        #[command(subcommand)]
        command: crate::profile::cli::ProfileCommand,
    },
    /// Run a versioned structured query supplied as a JSON object.
    Query {
        /// The request as one JSON object, e.g. `{"operation":"info"}`.
        request: String,
    },
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
        /// Omit verbose JSON outputSchema from tools/list and emit concise text summaries alongside structuredContent.
        #[arg(long, env = "XREF_MCP_COMPACT")]
        compact: bool,
    },
    /// Embedded Rust (`.dep-v0` / `cargo-auditable`), Go (`.go.buildinfo`), and toolchain provenance.
    Deps(crate::provenance::cli::DepsArgs),
    /// Internal: background `field` server for one binary, started by `xref field` (see `XREF_NO_DAEMON`).
    #[command(hide = true)]
    FieldDaemon,
    /// Functions, code size, data pointers, imports and panic locations.
    Stats,
    /// Function symbols whose name contains a pattern (non-stripped binaries).
    Sym {
        /// Substring of the raw (mangled) symbol name.
        pattern: String,
    },
    /// The function (exact `.eh_frame` range) containing each address.
    Func {
        /// Addresses to look up (`0x...` hex or decimal).
        #[arg(required = true, value_parser = parse_number)]
        addrs: Vec<u64>,
    },
    /// Code and data slots naming addresses (`0x...`) or text (anything else).
    Refs {
        /// Addresses (`0x...`) or texts to search references to.
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
        /// Texts to search for.
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Instructions with an immediate operand.
    Imm {
        /// Immediate value (`0x...` hex or decimal).
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
        /// Field displacements (`0x...` hex or decimal).
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
        /// Address whose callers and references to list.
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// Explicit observed-edge store tied to this binary; sample counts are not call counts.
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Calls and tail jumps of the function containing an address, in code order.
    Calls {
        /// An address inside the function.
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
    /// Fixed-size records (vtables) from an address, each 8-byte field with the relocated pointer that fills it.
    Table {
        /// Address of the first record.
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// Bytes per record (a multiple of 8).
        #[arg(long, value_parser = parse_number, default_value = "32")]
        stride: u64,
        /// Records to dump.
        #[arg(long, value_parser = parse_number, default_value = "1")]
        count: u64,
    },
    /// Constant and symbolic arguments at every call site of a function (rdi..r9 and stack0..N).
    Args {
        /// Function address or symbol name.
        addr: String,
        /// Maximum number of stack argument slots to inspect.
        #[arg(long, default_value_t = 4)]
        max: usize,
        /// Filter predicate to preflight against call-site arguments (e.g. "rdx == 0").
        #[arg(long)]
        filter: Option<String>,
    },
    /// Call sites binary-wide passing the constant N as an argument, grouped by callee with the other constants it receives there.
    Callargs {
        /// The constant (decimal or 0x hex), compared with the whole argument register or stack slot.
        #[arg(value_parser = parse_number)]
        value: u64,
        /// Only this argument: rdi, rsi, rdx, rcx, r8, r9 or stack0..stack7.
        #[arg(long, value_parser = crate::callargs::Slot::parse)]
        arg: Option<crate::callargs::Slot>,
        /// Only calls to this function (address or symbol name).
        #[arg(long)]
        callee: Option<String>,
        /// Call sites listed; every callee is summarized.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Function summary card: inputs, return registers, field stores, calls with arguments, error paths.
    Card {
        /// Target function address or symbol name.
        #[arg(value_name = "FN")]
        addr: String,
        /// Emit the function card as JSON.
        #[arg(long)]
        json: bool,
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
        /// Function where chains start (address or symbol name).
        from: String,
        /// Function where chains end (address or symbol name).
        to: String,
        /// Maximum call-chain depth (hops).
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// Explicit observed-edge store tied to this binary; sample counts are not call counts.
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Indented caller or callee tree of a function, with ranges and first panic locations.
    Tree {
        /// Root function (address or symbol name).
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
        /// Explicit observed-edge store tied to this binary; sample counts are not call counts.
        #[arg(long)]
        with_observed: Option<PathBuf>,
    },
    /// Counterpart of each function in another build of the binary, scored by shared locations, strings, immediates and call graph.
    #[command(visible_alias = "diff")]
    Match(crate::matching_cli::MatchArgs),
    /// Annotated disassembly of the function containing an address.
    Asm {
        /// An address inside the function; optional with --from, whose function is used.
        #[arg(value_parser = parse_number, required_unless_present = "from")]
        addr: Option<u64>,
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
        /// Addresses inside the functions to decompile.
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
        /// Emit only basic blocks that can reach this instruction address.
        #[arg(long = "only-paths-to", value_name = "ADDR", value_parser = parse_number)]
        only_paths_to: Option<u64>,
    },
    /// Backward program slice: minimal pseudo-C statements and branches reaching a target address or text.
    Slice {
        /// Function address or symbol name.
        addr: String,
        /// Target hex address, call name, field offset, or string substring inside the function.
        #[arg(long, required_unless_present = "to_field", conflicts_with = "to_field")]
        to: Option<String>,
        /// Target memory field: offset relative to a base register at an instruction address (`+0x10 of rax@0xVA`).
        #[arg(long = "to-field", value_name = "FIELD")]
        to_field: Option<String>,
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
        /// Functions in this binary to compare (addresses or symbol names).
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
        /// Text (or part of it) the variant's message contains.
        text: String,
        /// Also accept references this many bytes before the text (rustc format pieces start with a length byte).
        #[arg(long, default_value_t = 1)]
        back: u64,
    },
    /// Candidate checks that build an error: stores of the message's enum tag (value, width, layout), possible inner→outer conversions, and the conditions guarding each.
    Origin {
        /// Text (or part of it) the variant's message contains, or an address inside its `Display` arm.
        target: String,
        /// Also accept references this many bytes before the text (rustc format pieces start with a length byte).
        #[arg(long, default_value_t = 1)]
        back: u64,
        /// Conversion levels followed from the message's enum inward.
        #[arg(long, default_value_t = 3)]
        depth: usize,
        /// Sites rendered with their guarding pseudo-C; the rest are listed.
        #[arg(long, default_value_t = 12)]
        limit: usize,
        /// Also print the backward slice of every rendered site.
        #[arg(long)]
        slice: bool,
        /// Calls a tag passed as an argument is followed through after the function it is passed to.
        #[arg(long, default_value_t = 3)]
        arg_depth: usize,
    },
    /// Jump-table arms of the function containing an address for enum variant indices (all when
    /// none are given), with the texts they name and the calls each arm makes.
    Variant {
        /// An address inside the function.
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// Enum variant indices or inclusive ranges (`7 0x2c 218-222`); every index when omitted.
        indices: Vec<String>,
        /// Only the jump table at this address (`table` in the output).
        #[arg(long, value_parser = parse_number)]
        table: Option<u64>,
    },
    /// Jump-table indices whose arm holds each address (closest preceding arm of every table, best first).
    Arm {
        /// Code addresses to place in jump-table arms.
        #[arg(required = true, value_parser = parse_number)]
        addrs: Vec<u64>,
    },
    /// Rust source locations (panic `Location`s) the function containing an address passes.
    Src {
        /// An address inside the function.
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
    /// Functions passing source locations whose file contains a pattern (and optionally at one line).
    Where {
        /// Substring of the source file path.
        pattern: String,
        /// Only locations on this line.
        #[arg(long)]
        line: Option<u32>,
    },
    /// Distinct source files of the panic locations (optionally containing a pattern), with counts.
    Files {
        /// Substring of the source file path; all files when omitted.
        pattern: Option<String>,
    },
    /// Reconstructed struct field layout accessed via an argument register (and optionally callees receiving it).
    Layout {
        /// Function address or symbol name.
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
        /// Single serialized key to query; with only --within, every key that function passes.
        #[arg(required_unless_present_any = ["keys", "within"], conflicts_with = "keys")]
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
        /// Include partial key-reference seeds even when no direct-call path combines them.
        #[arg(long, requires = "keys")]
        exhaustive_key_seeds: bool,
        /// Maximum sibling helper functions selected into the discovery context (1..=8192).
        #[arg(long, default_value_t = crate::serde_fields::DEFAULT_KEY_FUNCTION_BUDGET)]
        max_functions: usize,
        /// Maximum decoded instructions per function for key/value analysis (1..=65536); also admits functions up to 8 bytes per instruction (32 KiB at the default).
        #[arg(long, default_value_t = crate::serde_fields::DEFAULT_KEY_INSTRUCTION_BUDGET)]
        max_instructions: usize,
        /// Show accessor instructions that may write the queried field.
        #[arg(long)]
        write: bool,
        /// Require writes to every comma-separated field name.
        #[arg(long, requires = "write", conflicts_with = "layout_only")]
        writes_all_of: Option<String>,
        /// Only writers whose offsets are relative to this kind of pointer (`returned`: a pointer
        /// returned by a call, such as a map lookup).
        #[arg(long, value_enum, default_value_t, requires = "write", conflicts_with = "layout_only")]
        writer_root: crate::serde_fields::WriterRoot,
        /// Maximum accessor rows (1..=128).
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// Skip the global accessor search while inspecting layout evidence.
        #[arg(long)]
        layout_only: bool,
    },
    /// Inspect a live Linux process via procfs (maps, address translation, and xref memory scan).
    Live(crate::live::cli::LiveCommand),
    /// Read typed data at a virtual address.
    Data {
        /// Virtual address to read from (`0x...` hex or decimal).
        #[arg(value_parser = parse_number)]
        va: u64,
        /// Data type to read (f64, f32, u64, u32, u16, u8, i64, i32, i16, i8, bytes, str).
        #[arg(long = "as")]
        as_type: crate::data::DataType,
        /// Number of elements to read (byte count for bytes; default 1, or 64 for bytes).
        #[arg(long)]
        count: Option<usize>,
        /// Maximum string length to read up to the first NUL (default 256).
        #[arg(long = "max-len", default_value_t = 256)]
        max_len: usize,
    },
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
