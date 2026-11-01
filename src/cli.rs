/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Command line. Addresses are ELF virtual addresses (objdump numbering): `0x` hex or decimal.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xref", version, about = "Ultra blazing fast cross-references of an x86-64 ELF binary")]
pub struct Cli {
    /// The ELF binary.
    #[arg(short, long, env = "XREF_BIN")]
    pub bin: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
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
    /// Instructions reading or writing a struct field: a non-stack memory operand with this displacement.
    Disp {
        #[arg(value_parser = parse_number)]
        value: u64,
        /// Only instructions writing the memory operand.
        #[arg(long)]
        write: bool,
        /// Only inside the function containing this address.
        #[arg(long = "in", value_parser = parse_number)]
        within: Option<u64>,
    },
    /// Direct calls and jumps to an address, and code taking its address or loading a slot holding it.
    Callers {
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
    /// Calls and tail jumps of the function containing an address, in code order.
    Calls {
        #[arg(value_parser = parse_number)]
        addr: u64,
    },
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
    /// Pseudo-C decompilation of the function containing an address.
    C {
        #[arg(value_parser = parse_number)]
        addr: u64,
        /// First address to print.
        #[arg(long, value_parser = parse_number)]
        from: Option<u64>,
        /// End address (exclusive).
        #[arg(long, value_parser = parse_number)]
        to: Option<u64>,
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
