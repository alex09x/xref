/*
 * XRef — Binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::aggregate::FunctionKey;
use super::analyze::Analysis;
use crate::image::Image;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
struct Line {
    text: String,
    samples: u64,
    percent_of_profile: f64,
    percent_of_function: f64,
}

pub fn write(
    analysis: &Analysis,
    image: &Image,
    function: u64,
    json: bool,
    min_samples: u64,
    percent: super::cli::PercentScale,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let locations = crate::locations::locations(image);
    let runtime = crate::runtime::RuntimeMap::detect(image);
    let (_, code) = crate::c::c_one(image, &locations, &runtime, function, None, None)?;
    let mut lines: Vec<_> = code
        .lines()
        .map(|text| Line { text: text.to_owned(), samples: 0, percent_of_profile: 0.0, percent_of_function: 0.0 })
        .collect();
    let key = FunctionKey { module: 1, start: Some(function) };
    let function_samples = analysis.aggregate.functions.get(&key).map_or(0, |counts| counts.self_samples);
    let mut ips: Vec<_> = analysis
        .aggregate
        .instructions
        .iter()
        .filter_map(|((owner, ip), count)| (*owner == key).then_some((*ip, *count)))
        .collect();
    ips.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut unmapped = 0_u64;
    let truncated = ips.len() > 128;
    for (index, (ip, count)) in ips.into_iter().enumerate() {
        if index >= 128 {
            unmapped = unmapped.saturating_add(count);
            continue;
        }
        let (_, marked) = crate::c::c_one_marked(image, &locations, &runtime, function, None, None, Some(ip))?;
        let mut target = marked.lines().filter(|line| line.contains(" /* @xref_slice_target */"));
        let Some(line) = target.next() else {
            unmapped = unmapped.saturating_add(count);
            continue;
        };
        if target.next().is_some() {
            unmapped = unmapped.saturating_add(count);
            continue;
        }
        let plain = line.replace(" /* @xref_slice_target */", "");
        let mut matching = lines.iter_mut().filter(|item| item.text == plain);
        let Some(item) = matching.next() else {
            unmapped = unmapped.saturating_add(count);
            continue;
        };
        if matching.next().is_some() {
            unmapped = unmapped.saturating_add(count);
            continue;
        }
        item.samples = item.samples.saturating_add(count);
    }
    for line in &mut lines {
        if analysis.aggregate.samples > 0 {
            line.percent_of_profile = super::report::percent(line.samples, analysis.aggregate.samples);
        }
        line.percent_of_function = super::report::percent(line.samples, function_samples);
    }
    if min_samples > 0 {
        lines.retain(|line| line.samples >= min_samples);
    }
    if json {
        serde_json::to_writer_pretty(
            &mut *out,
            &serde_json::json!({ "lines": lines, "unmapped_samples": unmapped, "instruction_budget_exhausted": truncated,
            "note": "pseudo-C mapping is approximate; optimized-away or ambiguous instructions remain unmapped" }),
        )?;
        writeln!(out)?;
    } else {
        writeln!(out, "pseudo-C attribution is approximate; {unmapped} samples not mapped to a unique statement")?;
        for line in lines {
            let scale = match percent {
                super::cli::PercentScale::Both => {
                    format!("{:>7.2}% function {:>7.2}% profile", line.percent_of_function, line.percent_of_profile)
                }
                super::cli::PercentScale::Function => format!("{:>7.2}% function", line.percent_of_function),
                super::cli::PercentScale::Profile => format!("{:>7.2}% profile", line.percent_of_profile),
            };
            writeln!(out, "{scale} {:>8} {}", line.samples, line.text)?;
        }
    }
    Ok(())
}
