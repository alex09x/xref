/*
 * XRef — Bounded trace input and output
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::cli::SymbolizeArgs;
use crate::{
    commands::Res,
    trace_analysis::{
        grouping::FoldedGroups,
        index::SymbolIndex,
        models::ObservedStore,
        observed::{MAX_STORE_BYTES, validate_store},
        stream::{TraceConfig, import_trace},
    },
};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

pub fn read_text(path: &Path, limit: usize) -> Result<String, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err(format!("input file exceeds {limit} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "input is not UTF-8".to_owned())
}

pub fn input_reader(path: &Path) -> Result<Box<dyn BufRead>, String> {
    if path == Path::new("-") {
        Ok(Box::new(BufReader::new(std::io::stdin())))
    } else {
        Ok(Box::new(BufReader::new(File::open(path).map_err(|e| e.to_string())?)))
    }
}

pub fn load_store(path: &Path, index: &SymbolIndex) -> Result<ObservedStore, String> {
    let text = read_text(path, MAX_STORE_BYTES)?;
    let store = serde_json::from_str(&text).map_err(|error| format!("invalid observed store: {error}"))?;
    validate_store(&store, index)?;
    Ok(store)
}

pub fn save_store(path: &Path, store: &ObservedStore) -> Res {
    let bytes = serde_json::to_vec_pretty(store)?;
    if bytes.len() > MAX_STORE_BYTES {
        return Err("observed store exceeds 32 MiB".into());
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
    let temp = parent.join(format!(".xref-observed-{}-{nonce}.tmp", std::process::id()));
    let result = (|| -> Res {
        let mut file = OpenOptions::new().create_new(true).write(true).open(&temp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        // Linking publishes a complete file and refuses to overwrite an existing destination.
        fs::hard_link(&temp, path)?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}

pub fn symbolize(index: &SymbolIndex, config: &TraceConfig<'_>, args: &SymbolizeArgs, out: &mut dyn Write) -> Res {
    let mut reader = input_reader(&args.trace.input)?;
    let mut groups = FoldedGroups::default();
    let collapsed = args.folded || args.group_by.is_some();
    let mut report = import_trace(&mut reader, index, config, |frames, weight| {
        if args.group_by.is_some() {
            return groups.add_caller(frames, weight);
        }
        if collapsed {
            return groups.add(frames, weight, args.group_callers);
        }
        if args.jsonl {
            serde_json::to_writer(&mut *out, &serde_json::json!({"type":"stack","frames":frames,"weight":weight}))
                .map_err(|e| e.to_string())?;
            writeln!(out).map_err(|e| e.to_string())?;
        } else {
            writeln!(out, "stack weight={weight} (leaf first)").map_err(|e| e.to_string())?;
            for frame in frames {
                let name =
                    frame.function.as_ref().map_or_else(|| "?".to_owned(), |f| format!("{}+{}", f.label, f.offset));
                let site = frame.call_site.as_ref().map(|site| format!(" call_site={site}")).unwrap_or_default();
                let source = frame
                    .source
                    .as_ref()
                    .map(|s| format!(" source_hint={}:{} ({})", s.file, s.line, s.evidence))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "  {} -> {} {} [{}]{site}{source}",
                    frame.input,
                    frame.static_address.as_deref().unwrap_or("-"),
                    name,
                    frame.status
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })?;
    if groups.truncated {
        report.stats.aggregation_truncated = true;
        report.warnings.push("folded_group_budget_exhausted_counts_partial".to_owned());
    }
    if collapsed {
        for (stack, count) in groups.groups {
            writeln!(out, "{stack} {count}")?;
        }
        eprintln!(
            "{} samples, {} unresolved frames; {}",
            report.stats.samples,
            report.stats.unresolved_frames,
            report.warnings.join("; ")
        );
    } else if args.jsonl {
        serde_json::to_writer(
            &mut *out,
            &serde_json::json!({"type":"summary","image":report.image,"stats":report.stats,"warnings":report.warnings,"identity_evidence":report.identity_evidence,"count_unit":report.count_unit}),
        )?;
        writeln!(out)?;
    } else {
        writeln!(out, "{} samples, {} unresolved frames", report.stats.samples, report.stats.unresolved_frames)?;
        for warning in report.warnings {
            writeln!(out, "warning: {warning}")?;
        }
    }
    Ok(())
}
