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

pub fn variants(image: &Image, addr: u64, indices: &[usize], out: &mut dyn Write) -> Res {
    let f = function(image, addr)?;
    let code = image.code(&f).ok_or("function outside the image")?;
    let found = tables(image, &f);
    if found.is_empty() {
        return Err(format!("no jump table in {:#x}..{:#x}", f.start, f.end).into());
    }
    let mut named = Vec::new();
    decode(code, f.start, |instruction| {
        if instruction.is_ip_rel_memory_operand()
            && let Some(text) = image.preview(instruction.ip_rel_memory_address())
        {
            named.push((instruction.ip(), text));
        }
    });
    for table in &found {
        for &index in indices {
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
            writeln!(
                out,
                "table {:#x}  variant {index} ({index:#x})  arm {arm:#x}..{end:#x}  {}",
                table.base,
                texts.join("  ")
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::arm_end;

    #[test]
    fn an_arm_ends_at_the_next_higher_arm_or_the_function_end() {
        let arms = [0x300, 0x100, 0x200, 0x100];
        assert_eq!(arm_end(&arms, 0x100, 0x400), 0x200);
        assert_eq!(arm_end(&arms, 0x200, 0x400), 0x300);
        assert_eq!(arm_end(&arms, 0x300, 0x400), 0x400);
        assert_eq!(arm_end(&arms, 0x200, 0x250), 0x250);
    }
}
