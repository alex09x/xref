/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `variant ADDR --names-from FN`: the names of an enum's variants, taken from a function that
//! writes them (its `Display`, `Serialize` or `Debug`), shown next to the arms of another
//! function's `match` on the same enum, such as a dispatcher. The two jump tables may number the
//! variants differently (a niche-encoded tag is `index + bias`), so an index is carried over
//! through the tag value when both tag loads are found.

use std::collections::HashMap;
use std::ops::Range;

use iced_x86::{Code, Instruction};

use crate::image::Image;
use crate::origin::dispatch::{Tag, tag_of};
use crate::scan::decode;
use crate::tables::{Table, tables};

/// Names kept per arm: the variant name and, for serde, its renamed form.
const NAMES_PER_ARM: usize = 2;

/// The names an enum-writing function gives each index of its largest jump table.
#[allow(clippy::struct_field_names)] // `names` are the names of each arm.
pub struct Names {
    pub function: u64,
    pub table: u64,
    pub tag: Option<Tag>,
    names: Vec<Vec<String>>,
}

/// `(ptr, len)` identifier literals in `range` of `listing`, in code order: passed in argument
/// registers, or stored as a pair on the stack (`mov [rsp+N], rax; mov qword ptr [rsp+N+8], len`)
/// for a call taking them by reference.
fn identifiers(image: &Image, listing: &[Instruction], range: &Range<u64>) -> Vec<String> {
    listing
        .iter()
        .enumerate()
        .filter(|(_, i)| range.contains(&i.ip()) && i.code() == Code::Lea_r64_m && i.is_ip_rel_memory_operand())
        .filter_map(|(at, i)| {
            crate::literal_len::literal_at(image, listing, i.ip()).or_else(|| stacked_literal(image, listing, at))
        })
        .filter(|text| text.len() <= 64 && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .collect()
}

/// The literal loaded by the `lea` at `listing[at]` when its address and an immediate length are
/// stored next to each other on the stack.
fn stacked_literal(image: &Image, listing: &[Instruction], at: usize) -> Option<String> {
    use iced_x86::{OpKind, Register};
    let lea = listing[at];
    let held = lea.op0_register().full_register();
    let stack_slot = |i: &Instruction| {
        (i.op0_kind() == OpKind::Memory && i.memory_base() == Register::RSP && i.memory_index() == Register::None)
            .then(|| i.memory_displacement64())
    };
    let near = listing.get(at + 1..(at + 4).min(listing.len()))?;
    let (store, slot) = near.iter().enumerate().find_map(|(k, i)| {
        (i.op1_kind() == OpKind::Register && i.op1_register().full_register() == held)
            .then(|| stack_slot(i))
            .flatten()
            .map(|slot| (k, slot))
    })?;
    let len = near[store + 1..].iter().find_map(|i| {
        (stack_slot(i) == Some(slot.wrapping_add(8))
            && matches!(i.op1_kind(), OpKind::Immediate32to64 | OpKind::Immediate32))
        .then(|| i.immediate(1))
    })?;
    let len = usize::try_from(len).ok().filter(|n| (1..=64).contains(n))?;
    let text = std::str::from_utf8(image.read(lea.ip_rel_memory_address(), len)?).ok()?;
    Some(text.to_owned())
}

impl Names {
    /// The names `function` writes per index of its largest jump table. A literal written by most
    /// arms (the enum's own name, a `"type"` key) names no single variant and is left out.
    pub fn collect(image: &Image, function: &Range<u64>) -> Result<Self, String> {
        let code = image.code(function).ok_or("function outside the image")?;
        let mut listing = Vec::new();
        decode(code, function.start, |instruction| listing.push(*instruction));
        let found = tables(image, function);
        let all_arms: Vec<u64> = found.iter().flat_map(|t| t.arms.iter().copied()).collect();
        let table = found
            .iter()
            .max_by_key(|t| t.arms.len())
            .ok_or_else(|| format!("no jump table in {:#x}..{:#x} to take names from", function.start, function.end))?;
        let per_arm: Vec<Vec<String>> = table
            .arms
            .iter()
            .map(|&arm| identifiers(image, &listing, &(arm..crate::variant::arm_end(&all_arms, arm, function.end))))
            .collect();
        let mut arms_naming: HashMap<&str, usize> = HashMap::new();
        for texts in &per_arm {
            let mut once: Vec<&str> = texts.iter().map(String::as_str).collect();
            once.dedup();
            for text in once {
                *arms_naming.entry(text).or_default() += 1;
            }
        }
        let common = |text: &str| per_arm.len() >= 4 && arms_naming.get(text).is_some_and(|&n| n * 2 > per_arm.len());
        let names = per_arm
            .iter()
            .map(|texts| {
                let mut kept: Vec<String> = Vec::new();
                for text in texts.iter().filter(|t| !common(t)) {
                    if kept.len() < NAMES_PER_ARM && !kept.contains(text) {
                        kept.push(text.clone());
                    }
                }
                kept
            })
            .collect();
        Ok(Self { function: function.start, table: table.base, tag: tag_of(image, function, table.dispatch), names })
    }

    /// The names of `index` of a table dispatched on `tag`: through the tag value when both tags
    /// are known, else by the same index when both tables have as many arms.
    pub fn of(&self, here: Option<&Tag>, arms: usize, index: usize) -> &[String] {
        let there = match (here, self.tag.as_ref()) {
            (Some(here), Some(there)) => here.value(index).map_or_else(
                || there.dataful.and_then(|d| usize::try_from(d).ok()),
                |value| {
                    let candidate = usize::try_from(value.wrapping_sub(there.bias) & there.mask()).ok();
                    candidate.filter(|&j| there.value(j) == Some(value))
                },
            ),
            _ => (arms == self.names.len()).then_some(index),
        };
        there.and_then(|j| self.names.get(j)).map_or(&[], Vec::as_slice)
    }

    /// How the indices of `table` (dispatched on `here`) are matched to the names.
    pub fn header(&self, table: &Table, here: Option<&Tag>) -> String {
        let tag = |tag: &Tag| {
            use std::fmt::Write as _;
            let mut text = format!("{} [{:?}+{:#x}]", tag.type_name(), tag.base, tag.displacement).to_ascii_lowercase();
            if tag.bias != 0 {
                let _ = write!(text, " = index + {:#x}", tag.bias);
            }
            if let Some(dataful) = tag.dataful {
                let _ = write!(text, ", dataful index {dataful}");
            }
            text
        };
        let how = match (here, self.tag.as_ref()) {
            (Some(here), Some(there)) => format!("by tag value: here {}, there {}", tag(here), tag(there)),
            _ if table.arms.len() == self.names.len() => {
                "by index (a tag load was not found; both tables have as many arms)".to_owned()
            }
            _ => format!(
                "not matched: a tag load was not found and the tables differ ({} and {} arms)",
                table.arms.len(),
                self.names.len()
            ),
        };
        format!("table {:#x}  names from {:#x} table {:#x}, {how}", table.base, self.function, self.table)
    }
}

#[cfg(test)]
#[path = "variant_names_tests.rs"]
mod tests;
