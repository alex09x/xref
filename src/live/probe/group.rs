/*
 * XRef — Stage L2 probe hit grouping by return site
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;
use std::io::Write;

use serde::Serialize;

use crate::live::probe::types::FetchedSample;
use crate::live::types::HexAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupBy {
    Ret,
}

pub fn parse_group_by(spec: &str) -> Result<GroupBy, String> {
    match spec.trim() {
        "ret" => Ok(GroupBy::Ret),
        other => Err(format!("unsupported --group-by '{other}': only 'ret' is supported")),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_site: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_function: Option<HexAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_symbol: Option<String>,
    pub hits: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fetched_samples: Vec<FetchedSample>,
}

pub fn build_group_histogram_from_probes(probes: &[crate::live::probe::types::ProbeTargetResult]) -> Vec<GroupEntry> {
    let mut groups: BTreeMap<Option<HexAddr>, GroupEntry> = BTreeMap::new();
    for probe in probes {
        for caller in &probe.callers {
            let entry = groups.entry(caller.return_static_va).or_insert_with(|| GroupEntry {
                return_site: caller.return_static_va,
                caller_function: caller.caller_function,
                caller_symbol: caller.caller_symbol.clone(),
                hits: 0,
                fetched_samples: Vec::new(),
            });
            entry.hits = entry.hits.saturating_add(caller.hits);
        }
        for sample in &probe.fetched_samples {
            if let Some(entry) = groups.get_mut(&sample.ret) {
                entry.fetched_samples.push(sample.clone());
            } else {
                let entry = groups.entry(sample.ret).or_insert_with(|| GroupEntry {
                    return_site: sample.ret,
                    caller_function: None,
                    caller_symbol: None,
                    hits: 1,
                    fetched_samples: Vec::new(),
                });
                entry.fetched_samples.push(sample.clone());
            }
        }
    }
    let mut list: Vec<GroupEntry> = groups.into_values().collect();
    list.sort_by(|a, b| {
        b.hits.cmp(&a.hits).then_with(|| match (&a.return_site, &b.return_site) {
            (Some(ra), Some(rb)) => ra.0.cmp(&rb.0),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        })
    });
    list
}

pub fn write_group_histogram(hist: &[GroupEntry], out: &mut dyn Write) -> std::io::Result<()> {
    for group in hist {
        let ret_str = group.return_site.map_or_else(|| "-".to_owned(), |v| format!("{:#x}", v.0));
        let fn_part = match (&group.caller_function, &group.caller_symbol) {
            (Some(f), Some(sym)) => format!(" (fn {:#x} {sym})", f.0),
            (Some(f), None) => format!(" (fn {:#x})", f.0),
            (None, _) => String::new(),
        };
        writeln!(out, "group ret {ret_str}{fn_part}  hits {}", group.hits)?;
        for sample in &group.fetched_samples {
            let values = sample
                .values
                .iter()
                .map(|v| format!("{}={:#x}", v.name, v.value.0))
                .collect::<Vec<_>>()
                .join(" ");
            let mark_str = sample.mark.as_deref().map_or_else(String::new, |m| format!("  mark {m:?}"));
            writeln!(out, "  fetch ts {}  {values}{mark_str}", sample.timestamp_ns)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::unreadable_literal)]
mod tests {
    use super::{build_group_histogram_from_probes, parse_group_by, write_group_histogram};
    use crate::live::probe::types::{CallerEntry, FetchedSample, FetchedValue, ProbeTargetResult, UnwindEntryStatus};
    use crate::live::types::HexAddr;

    #[test]
    fn parses_supported_group_by_keys() {
        assert!(parse_group_by("ret").is_ok());
        assert!(parse_group_by("invalid").is_err());
    }

    #[test]
    fn groups_hits_by_return_site_and_orders_by_hit_count() {
        let probe = ProbeTargetResult {
            input: HexAddr(0x1000),
            static_va: HexAddr(0x1000),
            runtime_va: HexAddr(0x1000),
            file_offset: HexAddr(0x1000),
            function_start: Some(HexAddr(0x1000)),
            function_end: Some(HexAddr(0x1010)),
            function_offset: Some(0),
            symbol: None,
            instruction_mnemonic: "push".to_owned(),
            unwind_entry_abi: UnwindEntryStatus::StandardRsp8RaMinus8,
            accepted_hits: 3,
            first_timestamp_ns: Some(100),
            last_timestamp_ns: Some(300),
            callers: vec![
                CallerEntry {
                    return_static_va: Some(HexAddr(0x401050)),
                    raw_return_runtime_va: HexAddr(0x401050),
                    caller_function: Some(HexAddr(0x401000)),
                    caller_symbol: Some("caller_a".to_owned()),
                    call_site_static_va: None,
                    call_verified: true,
                    hits: 1,
                    caveat: "verified",
                },
                CallerEntry {
                    return_static_va: Some(HexAddr(0x402050)),
                    raw_return_runtime_va: HexAddr(0x402050),
                    caller_function: Some(HexAddr(0x402000)),
                    caller_symbol: Some("caller_b".to_owned()),
                    call_site_static_va: None,
                    call_verified: true,
                    hits: 2,
                    caveat: "verified",
                },
            ],
            register_samples_truncated: false,
            register_samples: Vec::new(),
            fetched_samples: vec![
                FetchedSample {
                    timestamp_ns: 200,
                    va: Some(HexAddr(0x1000)),
                    tid: Some(42),
                    ret: Some(HexAddr(0x402050)),
                    mark: Some("phase1".to_owned()),
                    values: vec![FetchedValue { name: "val".to_owned(), value: HexAddr(2) }],
                },
            ],
            fetched_samples_truncated: false,
        };

        let hist = build_group_histogram_from_probes(&[probe]);
        assert_eq!(hist.len(), 2);
        // caller_b has 2 hits, should come first
        assert_eq!(hist[0].return_site, Some(HexAddr(0x402050)));
        assert_eq!(hist[0].hits, 2);
        assert_eq!(hist[0].caller_symbol.as_deref(), Some("caller_b"));
        assert_eq!(hist[0].fetched_samples.len(), 1);

        // caller_a has 1 hit
        assert_eq!(hist[1].return_site, Some(HexAddr(0x401050)));
        assert_eq!(hist[1].hits, 1);

        let mut buf = Vec::new();
        write_group_histogram(&hist, &mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(rendered.contains("group ret 0x402050 (fn 0x402000 caller_b)  hits 2"));
        assert!(rendered.contains("group ret 0x401050 (fn 0x401000 caller_a)  hits 1"));
        assert!(rendered.contains("fetch ts 200  val=0x2  mark \"phase1\""));
    }
}
