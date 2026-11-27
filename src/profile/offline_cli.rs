/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};

use super::{analyze, annotate, cli::ProfileCommand, diff, report};
use crate::image::Image;

pub fn run(
    image: &Image,
    bin: &std::path::Path,
    command: ProfileCommand,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        ProfileCommand::Report { profile, top, by, json, folded, within, window, merge_windows } => {
            if top == 0 || top > 10_000 {
                return Err("--top must be between 1 and 10000".into());
            }
            let mut input = BufReader::new(File::open(profile)?);
            let within = within
                .iter()
                .map(|name| crate::graph::resolve(image, name).map(|range| range.start))
                .collect::<Result<BTreeSet<_>, _>>()?;
            let analysis = analyze::analyze_windows(&mut input, image, &within, window, merge_windows)?;
            let heap = analysis.header.event == super::heap::EVENT;
            let alloc = super::heap::is_bytes_event(&analysis.header.event) && !heap;
            let off_cpu = analysis.header.event == super::sched::EVENT;
            // Checked before any output file is created.
            if alloc && !matches!(by, super::cli::GroupBy::Function) {
                return Err(
                    "a live alloc recording reports stacks and functions by bytes; --by is not supported for it".into(),
                );
            }
            if off_cpu && !matches!(by, super::cli::GroupBy::Function) {
                return Err("an off-CPU recording reports its stacks by time; --by is not supported for it".into());
            }
            if let Some(path) = folded {
                let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
                // Weighted recordings fold their stacks by weight (bytes, off-CPU nanoseconds); off-CPU
                // stacks keep the blocking library call, as in their report.
                if off_cpu {
                    super::sched::render::folded(&analysis, image, &mut file)?;
                } else if heap {
                    super::heap::render::folded(&analysis, image, &mut file)?;
                } else if alloc {
                    super::alloc::render::folded(&analysis, image, &mut file)?;
                } else {
                    report::folded(&analysis, image, &mut file)?;
                }
            }
            // For an allocation recording, `--within` keeps the stacks through those functions (the
            // analysis already filtered them); its report shows them by bytes, library callers kept.
            if heap && !within.is_empty() {
                // A heap subtree: what each callee of the `--within` functions holds.
                return super::heap::render::callees(&analysis, image, &within, top, json, out);
            }
            if off_cpu {
                return super::sched::render::snapshot(&analysis, image, top, json, out);
            }
            report::write(&analysis, image, top, by, json, out)
        }
        ProfileCommand::Annotate { profile, function, c, json, min_samples, percent } => {
            let mut input = BufReader::new(File::open(profile)?);
            let analysis = analyze::analyze(&mut input, image, &BTreeSet::new())?;
            annotate::write(&analysis, image, &function, c, json, min_samples, percent, out)
        }
        ProfileCommand::Diff { before, after, other, top, json, by: _, min_delta } => {
            let other_image = other.as_ref().map(|path| Image::load(path)).transpose()?;
            let sha = |image: &Image| {
                use sha2::Digest;
                crate::trace_analysis::index::hex_bytes(&sha2::Sha256::digest(&image.data))
            };
            diff::check_sides(
                (&before, &diff::recorded_image(&before)?),
                (&after, &diff::recorded_image(&after)?),
                &sha(image),
                other_image.as_ref().map(sha).as_deref(),
            )?;
            let mut input_before = BufReader::new(File::open(before)?);
            let mut input_after = BufReader::new(File::open(after)?);
            let old = analyze::analyze(&mut input_before, image, &BTreeSet::new())?;
            let new_image = other_image.as_ref().unwrap_or(image);
            let new = analyze::analyze(&mut input_after, new_image, &BTreeSet::new())?;
            let cross_build = old.header.image_sha256 != new.header.image_sha256;
            diff::write(image, new_image, &old, &new, cross_build, top, json, min_delta, out)
        }
        ProfileCommand::Import { input, out: path, base, maps, target_path, pid, tids } => {
            let options = super::import_text::Options {
                bin,
                input: &input,
                output: &path,
                base: base.as_deref(),
                maps: maps.as_deref(),
                target_path: target_path.as_deref(),
                pid,
                tids: &tids,
            };
            super::import_text::run(image, &options)?;
            writeln!(out, "profile imported to {}", path.display())?;
            Ok(())
        }
    }
}
