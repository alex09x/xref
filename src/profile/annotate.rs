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
}

pub fn write(
    analysis: &Analysis,
    image: &Image,
    query: &str,
    c: bool,
    json: bool,
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
        return super::annotate_c::write(analysis, image, function.start, json, out);
    }
    let code = image.code(&function).ok_or("function code unavailable")?;
    let key = FunctionKey { module: 1, start: Some(function.start) };
    let mut rows = Vec::new();
    crate::scan::decode(code, function.start, |instruction| {
        let samples = analysis.aggregate.instructions.get(&(key, instruction.ip())).copied().unwrap_or(0);
        let percent = super::report::percent(samples, analysis.aggregate.samples);
        rows.push(Instruction {
            address: instruction.ip(),
            text: crate::scan::format(instruction),
            samples,
            percent_of_profile: percent,
        });
    });
    if json {
        serde_json::to_writer_pretty(&mut *out, &rows)?;
        writeln!(out)?;
    } else {
        for row in rows {
            writeln!(out, "{:>7.2}% {:>8} {:#x}  {}", row.percent_of_profile, row.samples, row.address, row.text)?;
        }
    }
    Ok(())
}
