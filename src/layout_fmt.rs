/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Formatting and active-register discovery helpers for `xref layout`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::ops::Range;

use iced_x86::Register;

use crate::commands::Res;
use crate::expr::{ABI_ARGS, reg_name};
use crate::image::Image;
use crate::layout::{FieldInfo, scan_fn};
use crate::listing::describe_code;
use crate::runtime::RuntimeMap;

fn format_callee_list(image: &Image, rt: &RuntimeMap, set: &BTreeSet<(u64, &'static str)>, prefix: &str) -> String {
    let names: Vec<String> = set
        .iter()
        .take(3)
        .map(|&(c, arg)| {
            let label = rt.label(image, c).map_or_else(|| describe_code(image, c), str::to_owned);
            format!("{label}({arg})")
        })
        .collect();
    let suffix = if set.len() > 3 { format!(" +{}", set.len() - 3) } else { String::new() };
    format!("{prefix}{}{suffix}", names.join(", "))
}

pub fn render_layout(
    image: &Image,
    root: &Range<u64>,
    selected_reg: Register,
    selected_name: &str,
    fields: &BTreeMap<u64, FieldInfo>,
    hops: &BTreeSet<(i64, u64, &'static str)>,
    out: &mut dyn Write,
) -> Res {
    let rt = RuntimeMap::detect(image);
    let rlow = selected_name.to_ascii_lowercase();
    let callee_set: BTreeSet<u64> = hops.iter().map(|&(_, c, _)| c).collect();
    if callee_set.is_empty() {
        writeln!(out, "layout of {rlow} in {:#x}..{:#x}:", root.start, root.end)?;
    } else {
        writeln!(out, "layout of {rlow} in {:#x}..{:#x} (+{} callees):", root.start, root.end, callee_set.len())?;
        let hop_desc: Vec<String> = hops
            .iter()
            .take(5)
            .map(|&(delta, c, arg)| {
                let label = rt.label(image, c).map_or_else(|| describe_code(image, c), str::to_owned);
                if delta == 0 {
                    format!("{rlow} -> {label}({arg})")
                } else {
                    format!("{rlow}+{delta:#x} -> {label}({arg})")
                }
            })
            .collect();
        let more = if hops.len() > 5 { format!(" (+{} more)", hops.len() - 5) } else { String::new() };
        writeln!(out, "  forwarded: {}{more}", hop_desc.join(", "))?;
    }

    for (&off, info) in fields {
        let ty = if info.ty.is_empty() { "&sub" } else { info.ty };
        let mut notes = Vec::new();
        if info.leas > 0 {
            notes.push(format!("lea:{}", info.leas));
        }
        if let Some(st) = info.stride {
            notes.push(format!("stride={st:#x}"));
        }
        if !info.ptr_callees.is_empty() {
            notes.push(format_callee_list(image, &rt, &info.ptr_callees, "-> "));
        }
        if !info.val_callees.is_empty() {
            notes.push(format_callee_list(image, &rt, &info.val_callees, "val-> "));
        }
        if !info.via_callees.is_empty() {
            notes.push(format_callee_list(image, &rt, &info.via_callees, "via "));
        }
        if !info.checks.is_empty() {
            let checks: Vec<String> = info
                .checks
                .iter()
                .map(|(op, value)| if *op == "nonzero" { (*op).to_owned() } else { format!("{op} {value:#x}") })
                .collect();
            notes.push(format!("checks {}", checks.join(", ")));
        }
        let extra = if notes.is_empty() { String::new() } else { format!("  {}", notes.join("  ")) };
        writeln!(
            out,
            "  +{off:<6x}  size {:>2}  {ty:<4}  r:{:<2} w:{:<2}{extra}",
            info.width, info.reads, info.writes
        )?;
    }
    let span = fields.last_key_value().map_or(0, |(&off, info)| off + info.width.max(1) as u64);
    writeln!(out, "{} fields (min span {span:#x})", fields.len())?;

    let mut other_args = Vec::new();
    for &cand in &ABI_ARGS {
        if cand == selected_reg {
            continue;
        }
        let mut alt_fields = BTreeMap::new();
        let mut dummy = Vec::new();
        scan_fn(image, root, cand, 0, None, &mut alt_fields, &mut dummy);
        if !alt_fields.is_empty() {
            other_args.push(format!("{} ({} fields)", reg_name(cand), alt_fields.len()));
        }
    }
    if !other_args.is_empty() {
        writeln!(out, "other pointer args: {}  (use --reg <REG>)", other_args.join(", "))?;
    }
    Ok(())
}
