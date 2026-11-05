/*
 * XRef — Ambiguity-aware cross-build matching CLI
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::{
    commands::Res,
    graph::resolve,
    image::Image,
    matching::{MatchCandidate, MatchOptions},
};
use clap::Args;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Write, path::PathBuf};

#[derive(Args)]
pub struct MatchArgs {
    /// The other build of the binary to search for counterparts
    #[arg(long)]
    pub other: PathBuf,
    /// Functions in this binary to match (addresses or symbol names)
    #[arg(required = true)]
    pub addrs: Vec<String>,
    /// Number of candidates shown, 1..=128
    #[arg(long, default_value_t = 5)]
    pub top: usize,
    /// Runner-up / best structural score ratio triggering ambiguity (not a probability)
    #[arg(long, default_value_t = 0.95)]
    pub ambiguity_ratio: f64,
    /// Compare bounded plausible candidates by normalized pseudo-C similarity
    #[arg(long = "diff")]
    pub compare_pseudo_c: bool,
    /// Already matched caller pair: query-side caller followed by other-side caller
    #[arg(long,num_args=2,value_names=["QUERY_CALLER","OTHER_CALLER"])]
    pub context: Vec<String>,
    /// Emit the matches as JSON
    #[arg(long)]
    pub json: bool,
}

fn candidate_json(candidate: &MatchCandidate) -> Result<Value, serde_json::Error> {
    let mut value = serde_json::to_value(candidate)?;
    value["range"] = json!({"start":format!("{:#x}",candidate.range.start),"end":format!("{:#x}",candidate.range.end)});
    Ok(value)
}

pub fn run(image: &Image, args: &MatchArgs, out: &mut dyn Write) -> Res {
    if !(1..=128).contains(&args.top) {
        return Err("--top must be 1..=128".into());
    }
    let other = Image::load(&args.other)?;
    let context = match args.context.as_slice() {
        [] => None,
        [left, right] => Some((resolve(image, left)?.start, resolve(&other, right)?.start)),
        _ => return Err("--context needs query-side and other-side caller functions".into()),
    };
    let options =
        MatchOptions { ambiguity_ratio: args.ambiguity_ratio, compare_pseudo_c: args.compare_pseudo_c, context };
    if !args.json {
        if !options.compare_pseudo_c
            && options.context.is_none()
            && options.ambiguity_ratio.to_bits() == MatchOptions::default().ambiguity_ratio.to_bits()
        {
            return crate::matching::match_images(image, &other, &args.addrs, args.top, out);
        }
        return crate::matching::match_images_with_options(image, &other, &args.addrs, args.top, options, out);
    }
    let reports = crate::matching::match_images_report(image, &other, &args.addrs, options)?;
    let reports=reports.iter().map(|report|->Result<Value,serde_json::Error> {
        Ok(json!({"query":{"start":format!("{:#x}",report.query.start),"end":format!("{:#x}",report.query.end)},
            "candidates":report.candidates.iter().take(args.top).map(candidate_json).collect::<Result<Vec<_>,_>>()?,
            "selected":report.selected.as_ref().map(candidate_json).transpose()?,"ambiguous":report.ambiguous,
            "structural_score_margin":report.score_margin,"structural_runner_up_ratio":report.score_ratio,"warnings":report.warnings}))
    }).collect::<Result<Vec<_>,_>>()?;
    let digest = |bytes: &[u8]| crate::trace_analysis::index::hex_bytes(&Sha256::digest(bytes));
    serde_json::to_writer_pretty(
        &mut *out,
        &json!({"schema_version":1,"query_image_sha256":digest(&image.data),"other_image_sha256":digest(&other.data),"score_semantics":"heuristic_not_calibrated_probability_or_equivalence_proof","reports":reports}),
    )?;
    writeln!(out)?;
    Ok(())
}
