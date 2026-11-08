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
//! the callee (or a function it passes the value on to, up to `--arg-depth` calls deeper) stores
//! that argument with the tag's width at the tag offset of an object, or into an object it builds
//! on its stack; a store of the tag's width into another object's field makes it a candidate.
//! Spills into the callee's own frame are ignored. When the stack object is copied whole (#163),
//! the reads of the tag in the copy are its readers: after the copy, in the callees the copy is
//! passed to, and, for a copy into an object the function received, in its caller after the call.

use std::collections::HashMap;

use iced_x86::FlowControl;
use std::ops::Range;

use super::dispatch::Tag;
use crate::callargs::copy::Dest;
use crate::callargs::flow::{bit, function_code};
use crate::callargs::forward::{ArgStore, arg_stores};
use crate::callargs::pointer::{Reader, aliases_at, readers};
use crate::callargs::records::element_readers;
use crate::callargs::scan::{Slot, VOLATILE, calls};
use crate::expr::ABI_ARGS;
use crate::image::Image;

/// Calls a copied tag's object is followed into, in the caller, to find its readers.
const CALLER_READER_DEPTH: usize = 2;

pub struct Passed {
    pub ip: u64,
    pub function: Range<u64>,
    pub callee: u64,
    pub tail: bool,
    pub slot: Slot,
    pub store: ArgStore,
    /// The store is at the tag offset of an object, or into an object built on the stack.
    pub layout: bool,
    /// Reads of the tag in the copy of the stack object, wherever they were found.
    pub readers: Vec<Reader>,
    /// For a copy into a computed destination (a Vec element), reads of the same field of such
    /// records anywhere in the binary.
    pub element_readers: Vec<Reader>,
}

impl Passed {
    pub fn describe(&self) -> String {
        let stored_by = match self.store.via.split_last() {
            // `F (passed on as r9 to G, then as rsi)`: each hop but the last names its function.
            Some((last, before)) => {
                let hops: Vec<String> = before
                    .iter()
                    .map(|step| format!("as {} to {:#x}", step.slot, step.function))
                    .chain([format!("as {}", last.slot)])
                    .collect();
                format!("{:#x} (passed on {})", last.function, hops.join(", then "))
            }
            None => format!("{:#x}", self.callee),
        };
        let stack = if self.store.stack_object() { " into a stack object" } else { "" };
        let copied = self.store.copy.as_ref().map_or_else(
            || if self.store.stack_object() { " never read back there".to_owned() } else { String::new() },
            |copy| format!(", {}", copy.describe()),
        );
        format!(
            "passed as {} to {:#x}, stored by {stored_by} at {:#x} `{}`{stack}{copied}",
            self.slot, self.callee, self.store.ip, self.store.text
        )
    }
}

/// Calls passing `value` in an argument register or stack slot to a function that stores it `tag.width` bytes wide,
/// itself or after passing it on up to `depth` calls deeper.
pub fn passed(image: &Image, tag: &Tag, value: u64, depth: usize) -> Vec<Passed> {
    let found = calls(image, &|_, args| args.iter().any(|&(_, v)| v == value));
    let mut stores: HashMap<(u64, Slot), Vec<ArgStore>> = HashMap::new();
    let mut elements: HashMap<(u64, u64), Vec<Reader>> = HashMap::new();
    let mut passed = Vec::new();
    for call in found {
        for &(slot, _) in call.args.iter().filter(|&&(_, v)| v == value) {
            let known = stores
                .entry((call.callee, slot))
                .or_insert_with(|| arg_stores(image, call.callee, slot, tag.width, depth));
            let best = known
                .iter()
                .position(|store| store.at_object_offset(tag.displacement))
                // A field of an object built on the stack (copied out or passed by pointer later).
                .or_else(|| known.iter().position(ArgStore::stack_object))
                .map(|at| (at, true))
                // A spill to the callee's own frame says nothing; a field of another object might.
                .or_else(|| known.iter().position(ArgStore::object_field).map(|at| (at, false)));
            let Some((at, layout)) = best else { continue };
            let store = known[at].clone();
            let mut found = store.copy.as_ref().map(|copy| copy.readers.clone()).unwrap_or_default();
            found.extend(caller_readers(image, &call.function, call.ip, call.callee, &store, tag.width));
            found.sort_by_key(|reader| reader.ip);
            found.dedup_by_key(|reader| reader.ip);
            let element_readers = match &store.copy {
                Some(copy) if copy.dest == Dest::Computed => elements
                    .entry((copy.size, copy.offset))
                    .or_insert_with(|| element_readers(image, copy.size, copy.offset, tag.width))
                    .clone(),
                _ => Vec::new(),
            };
            passed.push(Passed {
                element_readers,
                ip: call.ip,
                function: call.function.clone(),
                callee: call.callee,
                tail: call.tail,
                slot,
                store,
                layout,
                readers: found,
            });
        }
    }
    passed
}

/// For a copy into an object the copying function received in an argument: the reads of the
/// tag's offset in its caller after the call (and in the callees the caller hands the object to).
fn caller_readers(
    image: &Image,
    producer: &Range<u64>,
    producer_call: u64,
    callee: u64,
    store: &ArgStore,
    width: usize,
) -> Vec<Reader> {
    let Some(copy) = &store.copy else { return Vec::new() };
    let Dest::Param(index) = copy.dest else { return Vec::new() };
    // The function that copied is the last hop; its caller is the hop before it, or the producer.
    let (parent, at_call) = match store.via.as_slice() {
        [] => (producer.start, producer_call),
        [only] => (callee, only.call),
        [.., before, last] => (before.function, last.call),
    };
    let Some((f, code)) = function_code(image, parent) else { return Vec::new() };
    let Some(at) = code.iter().position(|ins| ins.ip() == at_call) else { return Vec::new() };
    // After a tail jump control does not come back to this function.
    if !matches!(code[at].flow_control(), FlowControl::Call | FlowControl::IndirectCall) {
        return Vec::new();
    }
    let volatile = VOLATILE.iter().fold(0u16, |mask, r| mask | bit(*r).unwrap_or(0));
    let holders = aliases_at(image, &f, &code, at, ABI_ARGS[index]) & !volatile;
    if holders == 0 {
        return Vec::new();
    }
    readers(image, &f, &code, at + 1, holders, copy.offset, width, CALLER_READER_DEPTH)
}
