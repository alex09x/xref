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
        ProfileCommand::Report { profile, top, by, json, folded } => {
            if top == 0 || top > 10_000 {
                return Err("--top must be between 1 and 10000".into());
            }
            let mut input = BufReader::new(File::open(profile)?);
            let analysis = analyze::analyze(&mut input, image, &BTreeSet::new())?;
            if let Some(path) = folded {
                let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
                report::folded(&analysis, image, &mut file)?;
            }
            report::write(&analysis, image, top, by, json, out)
        }
        ProfileCommand::Annotate { profile, function, c, json } => {
            let mut input = BufReader::new(File::open(profile)?);
            let analysis = analyze::analyze(&mut input, image, &BTreeSet::new())?;
            annotate::write(&analysis, image, &function, c, json, out)
        }
        ProfileCommand::Diff { before, after, other, top, json } => {
            let mut input_before = BufReader::new(File::open(before)?);
            let mut input_after = BufReader::new(File::open(after)?);
            let old = analyze::analyze(&mut input_before, image, &BTreeSet::new())?;
            let other_image = other.as_ref().map(|path| Image::load(path)).transpose()?;
            let new_image = other_image.as_ref().unwrap_or(image);
            let new = analyze::analyze(&mut input_after, new_image, &BTreeSet::new())?;
            let cross_build = old.header.image_sha256 != new.header.image_sha256;
            diff::write(image, new_image, &old, &new, cross_build, top, json, out)
        }
        ProfileCommand::Import { input, out: path, base, maps, target_path, pid } => {
            let options = super::import_text::Options {
                bin,
                input: &input,
                output: &path,
                base: base.as_deref(),
                maps: maps.as_deref(),
                target_path: target_path.as_deref(),
                pid,
            };
            super::import_text::run(image, &options)?;
            writeln!(out, "profile imported to {}", path.display())?;
            Ok(())
        }
    }
}
