/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! xref: ultra blazing fast cross-references of an x86-64 ELF binary. Every query decodes all
//! functions (exact `.eh_frame` ranges) on every core, so no index is kept or cached.

mod c;
mod cli;
mod commands;
mod expr;
mod image;
mod listing;
mod locations;
mod reach;
mod scan;
mod source;
mod tables;
mod variant;

use std::io::{self, BufWriter, ErrorKind, Write};
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;

use crate::cli::Cli;
use crate::image::Image;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let started = Instant::now();
    let result = Image::load(&cli.bin).and_then(|image| {
        let loaded = started.elapsed();
        let mut out = BufWriter::new(io::stdout().lock());
        commands::run(&image, cli.command, &mut out)?;
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
