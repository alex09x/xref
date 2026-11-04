/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! xref: ultra blazing fast cross-references of an x86-64 ELF binary. Every query decodes all
//! functions (exact `.eh_frame` ranges) on every core, so no index is kept or cached.

mod api;
mod args;
mod c;
mod c_step;
mod callee_meta;
mod caller_ret;
mod calls;
mod card;
mod carry_alu;
mod carry_cond;
mod cfg;
mod cli;
mod commands;
mod cond;
mod diffc;
mod disp;
mod dump;
mod expr;
mod fields_c;
mod find;
mod float_alu;
mod goto_elim;
mod graph;
mod image;
mod image_format;
mod inline;
mod layout;
mod layout_fmt;
mod listing;
mod live;
mod locations;
mod loops;
mod macho;
mod matching;
mod matching_cli;
mod mcp;
mod profile;
mod reach;
mod reduce;
mod runtime;
mod scan;
mod serde_fields;
mod sig;
mod simplify;
mod slice;
mod slice_parse;
mod source;
mod ssa_cfg;
mod ssa_inline;
mod ssa_webs;
mod stack_anchors;
mod stack_frame;
mod tables;
#[cfg(test)]
mod tests;
mod trace_analysis;
mod trace_frontend;
mod type_facts;
mod type_prop;
mod unrotate;
mod variant;
mod wide_alu;

use std::io::{self, BufWriter, ErrorKind, Write};
use std::process::ExitCode;
use std::time::Instant;

use clap::{CommandFactory, Parser, error::ErrorKind as ClapErrorKind};

use crate::cli::Cli;
use crate::image::Image;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let cli::Command::Live(cmd) = &cli.command {
        let mut out = BufWriter::new(io::stdout().lock());
        let result = live::run(cli.bin.as_deref(), cmd, &mut out).and_then(|()| {
            out.flush()?;
            Ok(())
        });
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == ErrorKind::BrokenPipe) => {
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("xref: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(bin) = cli.bin.as_deref() else {
        Cli::command()
            .error(
                ClapErrorKind::MissingRequiredArgument,
                "the following required arguments were not provided:\n  --bin <BIN>",
            )
            .exit();
    };
    if let cli::Command::Mcp { allow_live_pid } = &cli.command {
        return match mcp::serve_with_live(bin, *allow_live_pid) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == ErrorKind::BrokenPipe) => {
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("xref: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if let cli::Command::Query { request } = &cli.command {
        let mut out = BufWriter::new(io::stdout().lock());
        return match api::run_cli(bin, request, &mut out) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) if error.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xref: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let started = Instant::now();
    let result = Image::load(bin).and_then(|image| {
        let loaded = started.elapsed();
        let mut out = BufWriter::new(io::stdout().lock());
        match cli.command {
            cli::Command::Symbolize(args) => {
                trace_frontend::cli::symbolize(&image, &bin.to_string_lossy(), &args, &mut out)?;
            }
            cli::Command::Edges { command } => {
                trace_frontend::cli::edges(&image, &bin.to_string_lossy(), &command, &mut out)?;
            }
            cli::Command::Profile { command } => {
                profile::offline_cli::run(&image, bin, command, &mut out)?;
            }
            command => commands::run(&image, command, &mut out)?,
        }
        out.flush()?;
        eprintln!("xref: load {loaded:.1?}, total {:.1?}", started.elapsed());
        Ok(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == ErrorKind::BrokenPipe) => {
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("xref: {error}");
            ExitCode::FAILURE
        }
    }
}
