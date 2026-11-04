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
struct Instruction {
    address: u64,
    #[serde(rename = "instruction")]
    text: String,
    samples: u64,
    percent_of_profile: f64,
    percent_of_function: f64,
}

#[allow(clippy::too_many_arguments)] // Rendering options are supplied by the CLI.
pub fn write(
    analysis: &Analysis,
    image: &Image,
    query: &str,
    c: bool,
    json: bool,
    min_samples: u64,
    percent: super::cli::PercentScale,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    if analysis.pt_aggregate.is_some() {
        return Err("separate PT instruction annotation is not yet supported".into());
    }
    let addr = if let Some(value) = crate::cli::hex_address(query) {
        value
    } else {
        let matches: Vec<_> =
            image.symbols.iter().filter(|(_, name)| name == query).map(|(address, _)| *address).collect();
        if matches.len() != 1 {
            return Err("function name must identify exactly one symbol".into());
        }
        matches[0]
    };
    let function = image.function_at(addr).ok_or("no function contains the requested address")?;
    if c {
        return super::annotate_c::write(analysis, image, function.start, json, min_samples, percent, out);
    }
    let code = image.code(&function).ok_or("function code unavailable")?;
    let key = FunctionKey { module: 1, start: Some(function.start) };
    let function_samples = analysis.aggregate.functions.get(&key).map_or(0, |counts| counts.self_samples);
    let mut rows = Vec::new();
    crate::scan::decode(code, function.start, |instruction| {
        let samples = analysis.aggregate.instructions.get(&(key, instruction.ip())).copied().unwrap_or(0);
        let percent = super::report::percent(samples, analysis.aggregate.samples);
        if samples < min_samples {
            return;
        }
        rows.push(Instruction {
            address: instruction.ip(),
            text: crate::scan::format(instruction),
            samples,
            percent_of_profile: percent,
            percent_of_function: super::report::percent(samples, function_samples),
        });
    });
    if json {
        serde_json::to_writer_pretty(&mut *out, &rows)?;
        writeln!(out)?;
    } else {
        for row in rows {
            let scale = match percent {
                super::cli::PercentScale::Both => {
                    format!("{:>7.2}% function {:>7.2}% profile", row.percent_of_function, row.percent_of_profile)
                }
                super::cli::PercentScale::Function => format!("{:>7.2}% function", row.percent_of_function),
                super::cli::PercentScale::Profile => format!("{:>7.2}% profile", row.percent_of_profile),
            };
            writeln!(out, "{scale} {:>8} {:#x}  {}", row.samples, row.address, row.text)?;
        }
    }
    Ok(())
}
