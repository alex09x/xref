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
mod call_order;
mod callargs;
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
mod const_value;
mod data;
mod diffc;
mod disp;
mod dump;
mod expr;
mod field_daemon;
mod field_result_cache;
mod fields_c;
mod find;
mod float_alu;
mod float_inline;
mod fmt_template;
mod goto_elim;
mod graph;
mod image;
mod image_format;
mod inline;
mod layout;
mod layout_fmt;
mod listing;
mod literal_len;
mod live;
mod locations;
mod loops;
mod macho;
mod matching;
mod matching_cli;
mod mcp;
mod only_paths;
mod origin;
mod pieces;
mod profile;
mod provenance;
mod reach;
mod reduce;
mod relr;
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
mod vtables;
mod wide_alu;
mod xmm_live;

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
    if let cli::Command::Mcp { allow_live_pid, compact } = &cli.command {
        return match mcp::serve_with_options(bin, *allow_live_pid, *compact) {
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
    let is_field = matches!(cli.command, cli::Command::Field { .. });
    let result_cache = is_field.then(|| field_result_cache::path_for(bin)).flatten();
    if let Some(code) = field_shortcut(&cli.command, bin, result_cache.as_deref(), started) {
        return code;
    }
    // `deps` and `data` read sections and segments only; they work without unwind tables.
    let sections_only = matches!(cli.command, cli::Command::Deps(_) | cli::Command::Data { .. });
    let loaded = if sections_only { Image::load_without_functions(bin) } else { Image::load(bin) };
    let result = loaded.and_then(|image| {
        let loaded = started.elapsed();
        let mut out = BufWriter::new(io::stdout().lock());
        if let Some(path) = &result_cache {
            let mut report = Vec::new();
            commands::run(&image, cli.command, &mut report)?;
            out.write_all(&report)?;
            out.flush()?;
            if field_result_cache::cacheable(&report) {
                field_result_cache::store(path, &report);
            }
            field_daemon::spawn_after(bin, started.elapsed());
        } else if is_field {
            run_loaded(&image, bin, cli.command, &mut out)?;
            out.flush()?;
            field_daemon::spawn_after(bin, started.elapsed());
        } else {
            run_loaded(&image, bin, cli.command, &mut out)?;
            out.flush()?;
        }
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

/// Answer without loading the image when possible: run the hidden field daemon, replay a stored
/// report for an identical `field` command, or let a running field daemon answer it.
fn field_shortcut(
    command: &cli::Command,
    bin: &std::path::Path,
    result_cache: Option<&std::path::Path>,
    started: Instant,
) -> Option<ExitCode> {
    if matches!(command, cli::Command::FieldDaemon) {
        return Some(match field_daemon::run(bin) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xref: {error}");
                ExitCode::FAILURE
            }
        });
    }
    if !matches!(command, cli::Command::Field { .. }) {
        return None;
    }
    if let Some(report) = result_cache.and_then(field_result_cache::load) {
        return Some(replay_cached_report(&report, started));
    }
    let report = field_daemon::query(bin)?;
    if let Some(path) = result_cache
        && field_result_cache::cacheable(&report)
    {
        field_result_cache::store(path, &report);
    }
    Some(replay_report(&report, started, "field daemon"))
}

/// Write a report replayed from the `field` result cache.
fn replay_cached_report(report: &[u8], started: Instant) -> ExitCode {
    replay_report(report, started, "cached result")
}

/// Write a `field` report produced elsewhere (result cache or field daemon).
fn replay_report(report: &[u8], started: Instant, source: &str) -> ExitCode {
    let mut out = io::stdout().lock();
    match out.write_all(report).and_then(|()| out.flush()) {
        Ok(()) => {
            eprintln!("xref: {source}, total {:.1?}", started.elapsed());
            ExitCode::SUCCESS
        }
        Err(error) if error.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xref: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Run an image command that writes to `out`.
fn run_loaded(
    image: &Image,
    bin: &std::path::Path,
    command: cli::Command,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        cli::Command::Symbolize(args) => trace_frontend::cli::symbolize(image, &bin.to_string_lossy(), &args, out)?,
        cli::Command::Edges { command } => trace_frontend::cli::edges(image, &bin.to_string_lossy(), &command, out)?,
        cli::Command::Profile { command } => profile::offline_cli::run(image, bin, command, out)?,
        command => commands::run(image, command, out)?,
    }
    Ok(())
}
