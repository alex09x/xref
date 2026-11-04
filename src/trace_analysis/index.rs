/*
 * XRef — Checked runtime mappings and stack frame attribution
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::BTreeMap;

use super::models::{FrameFunction, FrameKind, SourceHint, SymbolizedFrame, TraceIdentity};

#[derive(Clone, Debug)]
pub struct IndexedFunction {
    pub start: u64,
    pub end: u64,
    pub symbol: Option<String>,
    pub source_sites: Vec<(u64, SourceHint)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedCall {
    pub instruction: u64,
    pub caller: u64,
}

#[derive(Clone, Debug)]
pub struct IndexedSegment {
    pub va: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub executable: bool,
}

#[derive(Clone, Debug)]
pub struct SymbolIndex {
    pub identity: TraceIdentity,
    pub base: u64,
    pub functions: Vec<IndexedFunction>,
    pub calls_by_return: BTreeMap<u64, IndexedCall>,
    pub segments: Vec<IndexedSegment>,
    pub warnings: Vec<String>,
    symbol_functions: BTreeMap<String, Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeMapping {
    pub start: u64,
    pub end: u64,
    pub static_start: u64,
    pub pid: Option<u32>,
    pub executable: bool,
    pub evidence: String,
}

pub fn parse_hex(text: &str) -> Result<u64, String> {
    let raw = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid hexadecimal address: {text}"));
    }
    u64::from_str_radix(raw, 16).map_err(|_| "address exceeds u64".to_owned())
}

pub fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}

impl SymbolIndex {
    pub fn new(
        identity: TraceIdentity,
        base: u64,
        mut functions: Vec<IndexedFunction>,
        calls_by_return: BTreeMap<u64, IndexedCall>,
        segments: Vec<IndexedSegment>,
    ) -> Self {
        functions.sort_by_key(|function| (function.start, std::cmp::Reverse(function.end)));
        let mut symbol_functions: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for function in &functions {
            if let Some(symbol) = &function.symbol {
                symbol_functions.entry(symbol.clone()).or_default().push(function.start);
            }
        }
        for addresses in symbol_functions.values_mut() {
            addresses.sort_unstable();
            addresses.dedup();
        }
        Self { identity, base, functions, calls_by_return, segments, warnings: vec![], symbol_functions }
    }
    pub fn validate_identity(&self, trace_build_id: Option<&str>) -> Result<bool, String> {
        let Some(actual) = trace_build_id else { return Ok(false) };
        let expected = self.identity.build_id.as_deref().ok_or("selected image has no build ID to verify")?;
        if !expected.eq_ignore_ascii_case(actual) {
            return Err("trace_build_id_mismatch".to_owned());
        }
        Ok(true)
    }

    pub fn mappings_from_base(&self, runtime_base: u64) -> Result<Vec<RuntimeMapping>, String> {
        self.segments
            .iter()
            .map(|segment| {
                let relative = segment.va.checked_sub(self.base).ok_or("segment precedes image base")?;
                let start = runtime_base.checked_add(relative).ok_or("runtime mapping address overflow")?;
                let end = start.checked_add(segment.mem_size).ok_or("runtime mapping end overflow")?;
                Ok(RuntimeMapping {
                    start,
                    end,
                    static_start: segment.va,
                    pid: None,
                    executable: segment.executable,
                    evidence: "caller_supplied_runtime_image_base".to_owned(),
                })
            })
            .collect()
    }

    pub fn mapping_from_file_offset(
        &self,
        start: u64,
        len: u64,
        offset: u64,
        pid: Option<u32>,
        executable: bool,
        evidence: &str,
    ) -> Result<RuntimeMapping, String> {
        let mut candidates = self.segments.iter().filter_map(|segment| {
            let page_offset = segment.file_offset & !4095;
            let file_end = segment.file_offset.checked_add(segment.file_size)?.checked_add(4095)? & !4095;
            if offset < page_offset || offset >= file_end || executable != segment.executable {
                return None;
            }
            (segment.va & !4095).checked_add(offset - page_offset)
        });
        let static_start = candidates.next().ok_or("mapping file offset has no compatible load segment")?;
        if candidates.any(|value| value != static_start) {
            return Err("mapping file offset has ambiguous load segment translations".to_owned());
        }
        Ok(RuntimeMapping {
            start,
            end: start.checked_add(len).ok_or("mapping end overflow")?,
            static_start,
            pid,
            executable,
            evidence: evidence.to_owned(),
        })
    }

    fn function_at(&self, address: u64) -> Option<&IndexedFunction> {
        let end = self.functions.partition_point(|f| f.start <= address);
        self.functions[..end].iter().rev().take(64).find(|f| address < f.end)
    }

    pub fn frame(
        &self,
        input: &str,
        kind: FrameKind,
        pid: Option<u32>,
        mappings: &[RuntimeMapping],
    ) -> SymbolizedFrame {
        let kind = if kind != FrameKind::Symbol && input.starts_with("fn_") { FrameKind::Static } else { kind };
        let kind = if kind == FrameKind::Auto { FrameKind::Instruction } else { kind };
        let mut frame = SymbolizedFrame {
            input: input.chars().take(256).collect(),
            kind,
            runtime_address: None,
            static_address: None,
            mapping_evidence: None,
            function: None,
            call_site: None,
            call_site_evidence: None,
            source: None,
            status: "unresolved_address".to_owned(),
        };
        let address = if kind == FrameKind::Symbol {
            let matches = self.symbol_functions.get(input);
            if matches.is_none_or(|addresses| addresses.len() != 1) {
                "unknown_or_ambiguous_symbol".clone_into(&mut frame.status);
                return frame;
            }
            matches.and_then(|addresses| addresses.first()).copied().unwrap_or(0)
        } else {
            let token = input.strip_prefix("fn_").unwrap_or(input);
            let Ok(address) = parse_hex(token) else { return frame };
            if kind == FrameKind::Static || input.starts_with("fn_") {
                address
            } else {
                frame.runtime_address = Some(format!("{address:#x}"));
                let mapping_address =
                    if kind == FrameKind::ReturnAddress { address.saturating_sub(1) } else { address };
                let matches: Vec<_> = mappings
                    .iter()
                    .filter(|m| {
                        m.start <= mapping_address && mapping_address < m.end && (m.pid.is_none() || m.pid == pid)
                    })
                    .collect();
                if matches.len() != 1 {
                    "outside_target_or_ambiguous_mapping".clone_into(&mut frame.status);
                    return frame;
                }
                let mapping = matches[0];
                frame.mapping_evidence = Some(mapping.evidence.clone());
                if !mapping.executable {
                    "non_executable_mapping".clone_into(&mut frame.status);
                    return frame;
                }
                let Some(value) = mapping.static_start.checked_add(address - mapping.start) else { return frame };
                value
            }
        };
        frame.static_address = Some(format!("{address:#x}"));
        let lookup = if kind == FrameKind::ReturnAddress { address.checked_sub(1) } else { Some(address) };
        let Some(function) = lookup.and_then(|value| self.function_at(value)) else {
            "mapped_address_without_fde".clone_into(&mut frame.status);
            return frame;
        };
        frame.function = Some(FrameFunction {
            start: format!("{:#x}", function.start),
            end: format!("{:#x}", function.end),
            offset: format!("{:#x}", address.saturating_sub(function.start)),
            symbol: function.symbol.clone(),
            label: format!("fn_{:x}", function.start),
            range_evidence: "fde_not_source_function".to_owned(),
        });
        if kind == FrameKind::ReturnAddress
            && let Some(call) = self.calls_by_return.get(&address).filter(|call| call.caller == function.start)
        {
            frame.call_site = Some(format!("{:#x}", call.instruction));
            frame.call_site_evidence =
                Some("exact_decoded_call_end_matches_return_address_not_immediate_caller_proof".to_owned());
        }
        frame.source = function
            .source_sites
            .iter()
            .filter(|(site, _)| Some(*site) <= lookup)
            .max_by_key(|(site, _)| *site)
            .map(|(_, source)| source.clone());
        "resolved".clone_into(&mut frame.status);
        frame
    }
}
