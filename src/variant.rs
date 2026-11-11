/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `variant`: the inverse of `error` — the jump-table arms of a function for given indices and
//! the texts each arm names, e.g. the message of an enum variant in its `Display`.

use std::io::Write;

use crate::commands::{Res, function};
use crate::image::Image;
use crate::scan::decode;
use crate::tables::tables;

/// End of the arm starting at `arm`: the next higher arm of the table, or the function end.
pub fn arm_end(arms: &[u64], arm: u64, function_end: u64) -> u64 {
    arms.iter().copied().filter(|other| *other > arm).min().unwrap_or(function_end).min(function_end)
}

/// The jump-table indices whose arm holds each address, closest arm first.
pub fn arms(image: &Image, addrs: &[u64], out: &mut dyn Write) -> Res {
    for &addr in addrs {
        let f = function(image, addr)?;
        let found = tables(image, &f);
        let mut ranked: Vec<_> =
            found.iter().filter_map(|table| crate::commands::closest_arm(std::slice::from_ref(table), addr)).collect();
        ranked.sort_by_key(|(distance, ..)| *distance);
        if ranked.is_empty() {
            writeln!(out, "{addr:#x}  in {:#x}  no jump-table arm", f.start)?;
        }
        for (distance, table, indices, arm) in ranked {
            let variants: Vec<String> = indices.iter().map(|i| format!("{i} ({i:#x})")).collect();
            writeln!(
                out,
                "{addr:#x}  in {:#x}  variant {}  table {:#x} (dispatch {:#x})  arm {arm:#x} +{distance:#x}",
                f.start,
                variants.join(", "),
                table.base,
                table.dispatch
            )?;
        }
    }
    Ok(())
}

/// Parses variant indices: `7`, `0x2c`, and inclusive ranges `218-222`.
pub fn parse_indices(specs: &[String]) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for spec in specs {
        let number = |s: &str| {
            crate::cli::parse_number(s)
                .ok()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(|| format!("invalid variant index {s:?}"))
        };
        match spec.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (number(lo)?, number(hi)?);
                if lo > hi || hi - lo > MAX_RANGE {
                    return Err(format!("invalid variant range {spec:?} (LO-HI, at most {MAX_RANGE} apart)"));
                }
                out.extend(lo..=hi);
            }
            None => out.push(number(spec)?),
        }
    }
    Ok(out)
}

const MAX_RANGE: usize = 4096;

/// What an arm does: the calls and tail jumps inside it, or where it jumps in the function.
fn arm_handlers(flow: &[(u64, Flow)], arm: u64, end: u64) -> String {
    let inside: Vec<&Flow> = flow.iter().filter(|(ip, _)| (arm..end).contains(ip)).map(|(_, f)| f).collect();
    let calls: Vec<String> = inside
        .iter()
        .filter_map(|f| match f {
            Flow::Call(t) => Some(format!("{t:#x}")),
            Flow::Tail(t) => Some(format!("tail {t:#x}")),
            Flow::Jump(_) => None,
        })
        .collect();
    if !calls.is_empty() {
        let mut runs: Vec<(String, usize)> = Vec::new();
        for call in calls {
            match runs.last_mut() {
                Some((last, n)) if *last == call => *n += 1,
                _ => runs.push((call, 1)),
            }
        }
        let parts: Vec<String> = runs.into_iter().map(|(c, n)| if n > 1 { format!("{c} x{n}") } else { c }).collect();
        return format!("calls {}", parts.join(", "));
    }
    inside
        .iter()
        .find_map(|f| if let Flow::Jump(t) = f { Some(format!("-> {t:#x}")) } else { None })
        .unwrap_or_default()
}

enum Flow {
    Call(u64),
    Tail(u64),
    Jump(u64),
}

/// The arms of the function's jump tables for `indices` (every index when empty), each with the
/// texts it names and its handlers (calls, tail jumps, or the in-function jump it takes).
pub fn variants(image: &Image, addr: u64, indices: &[usize], table_base: Option<u64>, out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let found: Vec<_> = tables(image, &f).into_iter().filter(|t| table_base.is_none_or(|b| t.base == b)).collect();
    if found.is_empty() {
        let which = table_base.map_or_else(String::new, |b| format!(" at {b:#x}"));
        return Err(format!("no jump table{which} in {:#x}..{:#x}", f.start, f.end).into());
    }
    let mut named = Vec::new();
    let mut flow = Vec::new();
    let mut listing: Vec<iced_x86::Instruction> = Vec::new();
    decode(code, f.start, |instruction| {
        listing.push(*instruction);
        if instruction.is_ip_rel_memory_operand()
            && let Some(text) = image.preview(instruction.ip_rel_memory_address())
        {
            named.push((instruction.ip(), text));
        }
        let target = crate::graph::call_target(image, instruction);
        match (instruction.flow_control(), target) {
            (iced_x86::FlowControl::Call | iced_x86::FlowControl::IndirectCall, Some(t)) => {
                flow.push((instruction.ip(), Flow::Call(t)));
            }
            (iced_x86::FlowControl::UnconditionalBranch | iced_x86::FlowControl::IndirectBranch, Some(t)) => {
                let kind = if (f.start..f.end).contains(&t) { Flow::Jump(t) } else { Flow::Tail(t) };
                flow.push((instruction.ip(), kind));
            }
            _ => {}
        }
    });
    let named: Vec<(u64, String)> = named
        .into_iter()
        .map(|(ip, text)| match crate::literal_len::literal_len(&listing, ip) {
            Some(len) => (ip, text.chars().take(len).collect()),
            None => (ip, text),
        })
        .collect();
    for table in &found {
        let all: Vec<usize>;
        let wanted = if indices.is_empty() {
            all = (0..table.arms.len()).collect();
            &all
        } else {
            indices
        };
        for &index in wanted {
            let Some(&arm) = table.arms.get(index) else {
                writeln!(
                    out,
                    "table {:#x}  variant {index} ({index:#x})  outside {} arms",
                    table.base,
                    table.arms.len()
                )?;
                continue;
            };
            let end = arm_end(&table.arms, arm, f.end);
            let texts: Vec<String> =
                named.iter().filter(|(ip, _)| (arm..end).contains(ip)).map(|(_, text)| format!("{text:?}")).collect();
            let handlers = arm_handlers(&flow, arm, end);
            let line = format!(
                "table {:#x}  variant {index} ({index:#x})  arm {arm:#x}..{end:#x}  {handlers}  {}",
                table.base,
                texts.join("  ")
            );
            writeln!(out, "{}", line.trim_end())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Flow, arm_end, arm_handlers, parse_indices};

    #[test]
    fn indices_take_numbers_and_inclusive_ranges() {
        let specs: Vec<String> = ["210", "0xd3", "218-222"].iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(parse_indices(&specs), Ok(vec![210, 211, 218, 219, 220, 221, 222]));
        assert!(parse_indices(&["5-3".to_owned()]).is_err());
        assert!(parse_indices(&["x".to_owned()]).is_err());
    }

    #[test]
    fn an_arm_is_described_by_its_calls_else_its_jump() {
        let flow = [
            (0x110, Flow::Call(0x9000)),
            (0x114, Flow::Call(0x9000)),
            (0x118, Flow::Tail(0x9100)),
            (0x210, Flow::Jump(0x500)),
        ];
        assert_eq!(arm_handlers(&flow, 0x100, 0x200), "calls 0x9000 x2, tail 0x9100");
        assert_eq!(arm_handlers(&flow, 0x200, 0x300), "-> 0x500");
        assert_eq!(arm_handlers(&flow, 0x300, 0x400), "");
    }

    #[test]
    fn an_arm_ends_at_the_next_higher_arm_or_the_function_end() {
        let arms = [0x300, 0x100, 0x200, 0x100];
        assert_eq!(arm_end(&arms, 0x100, 0x400), 0x200);
        assert_eq!(arm_end(&arms, 0x200, 0x400), 0x300);
        assert_eq!(arm_end(&arms, 0x300, 0x400), 0x400);
        assert_eq!(arm_end(&arms, 0x200, 0x250), 0x250);
    }
}
