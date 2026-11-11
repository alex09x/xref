/*
 * XRef — name the whole stack object behind `&slot_N` passed to a call
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A call that takes `&slot_130` may read more than `slot_130`: a 20-byte key is stored as
//! `slot_130` (16 bytes) and `slot_140` (4 bytes) and only the first one appears in the call.
//! When the stores right before the call fill adjacent slots, a comment above the call names
//! them, with the value each one holds at that call:
//!
//! ```text
//! /* &slot_130 passes the object stored above: slot_130 = slot_60, slot_140 = slot_70 */
//! ```

use std::collections::BTreeMap;

use crate::expr::stack_name;
use crate::stack_frame::StackFrame;

/// Stack offset named by `slot_1f0` / `slot_m28`.
fn slot_offset(name: &str) -> Option<i64> {
    let hex = name.strip_prefix("slot_")?;
    hex.strip_prefix('m')
        .map_or_else(|| i64::from_str_radix(hex, 16).ok(), |neg| i64::from_str_radix(neg, 16).ok().map(|v| -v))
}

/// `slot_N = RHS;` at the start of a statement line: the slot offset and RHS.
fn slot_store(line: &str) -> Option<(i64, &str)> {
    let (lhs, rhs) = line.trim_start().split_once(" = ")?;
    let off = slot_offset(lhs).filter(|_| lhs.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))?;
    Some((off, rhs.trim_end().strip_suffix(';')?))
}

/// Ends the backward scan: a label, a block edge, or another statement passing a slot address.
fn scan_stops_at(line: &str) -> bool {
    let t = line.trim();
    t.ends_with(':') || t.ends_with('{') || t.starts_with('}') || t.contains("&slot_")
}

/// Every `&slot_N` in `line`, by offset.
fn passed_slots(line: &str) -> Vec<i64> {
    line.match_indices("&slot_")
        .filter_map(|(at, _)| {
            let rest = &line[at + 1..];
            let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(rest.len());
            slot_offset(&rest[..end])
        })
        .collect()
}

/// The comment for `&slot_<base>` when the stores above fill more than that slot.
fn object_note(frame: &StackFrame, base: i64, stores: &BTreeMap<i64, String>) -> Option<String> {
    let width = |off: i64| i64::from(frame.slots.get(&off).map_or(8, |s| s.max_width.clamp(1, 16)));
    let mut end = base.checked_add(width(base))?;
    let mut parts = vec![format!("{} = {}", stack_name(base), stores.get(&base)?)];
    for (&off, rhs) in stores.range(base + 1..) {
        if off > end {
            break;
        }
        parts.push(format!("{} = {rhs}", stack_name(off)));
        end = end.max(off + width(off));
    }
    (parts.len() > 1)
        .then(|| format!("/* &{} passes the object stored above: {} */", stack_name(base), parts.join(", ")))
}

/// Adds the object comment above each call line that passes an address-taken slot whose
/// neighbours were stored just before it.
pub(super) fn annotate_passed_objects(frame: &StackFrame, lines: &mut Vec<String>) {
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let bases: Vec<i64> =
            passed_slots(line).into_iter().filter(|off| frame.slots.get(off).is_some_and(|s| s.addr_taken)).collect();
        if bases.is_empty() || !line.contains('(') || slot_store(line).is_some_and(|(_, r)| !r.contains('(')) {
            i += 1;
            continue;
        }
        let mut stores: BTreeMap<i64, String> = BTreeMap::new();
        for prev in lines[..i].iter().rev() {
            if scan_stops_at(prev) {
                break;
            }
            if let Some((off, rhs)) = slot_store(prev) {
                stores.entry(off).or_insert_with(|| rhs.to_owned());
            }
        }
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let notes: Vec<String> =
            bases.iter().filter_map(|&b| object_note(frame, b, &stores)).map(|n| format!("{indent}{n}")).collect();
        let added = notes.len();
        lines.splice(i..i, notes);
        i += added + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack_frame::StackSlot;

    fn frame(slots: &[(i64, u8, bool)]) -> StackFrame {
        let mut f = StackFrame::default();
        for &(offset, max_width, addr_taken) in slots {
            let mut slot = StackSlot::default();
            (slot.offset, slot.max_width, slot.addr_taken) = (offset, max_width, addr_taken);
            f.slots.insert(offset, slot);
        }
        f
    }

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_owned).collect()
    }

    #[test]
    fn names_the_object_each_call_reads() {
        let f = frame(&[(0x130, 16, true), (0x140, 4, false), (0x60, 16, false)]);
        let mut body = lines(
            "  slot_140 = *(u32 *)(ptr_18 + 16);\n  slot_130 = *(u128 *)(ptr_18);\n  ptr_14 = ptr_2 + 0x14d8;\n  fn_54e1470(ptr_14, &slot_130);\nL_5866d36:\n  slot_140 = slot_70;\n  slot_130 = slot_60;\n  const u8 *ptr_21 = fn_54e1470(ptr_14, &slot_130);",
        );
        annotate_passed_objects(&f, &mut body);
        assert_eq!(
            body[3],
            "  /* &slot_130 passes the object stored above: slot_130 = *(u128 *)(ptr_18), slot_140 = *(u32 *)(ptr_18 + 16) */"
        );
        assert_eq!(body[8], "  /* &slot_130 passes the object stored above: slot_130 = slot_60, slot_140 = slot_70 */");
        assert_eq!(body[9], "  const u8 *ptr_21 = fn_54e1470(ptr_14, &slot_130);");
    }

    #[test]
    fn stays_silent_for_a_single_slot_or_a_gap_or_a_slot_not_taken() {
        let f = frame(&[(0x130, 16, true), (0x150, 8, false), (0x20, 8, false), (0x28, 8, false)]);
        let mut body = lines(
            "  slot_130 = v_1;\n  slot_150 = v_2;\n  fn_1(&slot_130);\n  slot_20 = v_3;\n  slot_28 = v_4;\n  fn_2(&slot_20);",
        );
        let before = body.clone();
        annotate_passed_objects(&f, &mut body);
        assert_eq!(body, before);
    }

    #[test]
    fn a_label_or_an_earlier_address_use_ends_the_store_window() {
        let f = frame(&[(0x10, 8, true), (0x18, 8, false)]);
        let mut body = lines("  slot_18 = v_9;\nL_1:\n  slot_10 = v_1;\n  fn_1(&slot_10);");
        annotate_passed_objects(&f, &mut body);
        assert_eq!(body.len(), 4);
        assert_eq!(slot_offset("slot_m28"), Some(-0x28));
        assert_eq!(passed_slots("f(&slot_10, &slot_m8)"), vec![0x10, -8]);
    }
}
