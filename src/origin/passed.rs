/*
 * XRef — Enum tags passed as call arguments
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! A producer may pass the tag to a helper rather than store it (#151): `h(out, .., status)` with
//! `mov r9d, 0x27` before the call, and `h` writing `r9b` into the tag. Such a call is a site when
//! the callee (or the function it passes the value on to) stores that argument with the tag's
//! width at the tag offset of an object; a store of the tag's width into another object's field
//! makes it a candidate. Spills into the callee's own frame are ignored.

use std::collections::HashMap;
use std::ops::Range;

use super::dispatch::Tag;
use crate::callargs::forward::{ArgStore, arg_stores};
use crate::callargs::scan::{Slot, calls};
use crate::image::Image;

pub struct Passed {
    pub ip: u64,
    pub function: Range<u64>,
    pub callee: u64,
    pub tail: bool,
    pub slot: Slot,
    pub store: ArgStore,
    /// The store is at the tag offset of an object.
    pub layout: bool,
}

impl Passed {
    pub fn describe(&self) -> String {
        let stored_by = match self.store.via {
            Some((target, slot)) => format!("{target:#x} (passed on as {slot})"),
            None => format!("{:#x}", self.callee),
        };
        format!(
            "passed as {} to {:#x}, stored by {stored_by} at {:#x} `{}`",
            self.slot, self.callee, self.store.ip, self.store.text
        )
    }
}

/// Register-argument calls passing `value` to a function that stores it `tag.width` bytes wide.
pub fn passed(image: &Image, tag: &Tag, value: u64) -> Vec<Passed> {
    let found = calls(image, &|_, args| args.iter().any(|&(slot, v)| matches!(slot, Slot::Reg(_)) && v == value));
    let mut stores: HashMap<(u64, Slot), Vec<ArgStore>> = HashMap::new();
    let mut passed = Vec::new();
    for call in found {
        for &(slot, _) in call.args.iter().filter(|&&(slot, v)| matches!(slot, Slot::Reg(_)) && v == value) {
            let known = stores
                .entry((call.callee, slot))
                .or_insert_with(|| arg_stores(image, call.callee, slot, tag.width, true));
            let best = known
                .iter()
                .position(|store| store.at_object_offset(tag.displacement))
                .map(|at| (at, true))
                // A spill to the callee's own frame says nothing; a field of another object might.
                .or_else(|| known.iter().position(ArgStore::object_field).map(|at| (at, false)));
            let Some((at, layout)) = best else { continue };
            passed.push(Passed {
                ip: call.ip,
                function: call.function.clone(),
                callee: call.callee,
                tail: call.tail,
                slot,
                store: known[at].clone(),
                layout,
            });
        }
    }
    passed
}
