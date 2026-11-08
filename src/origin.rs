/*
 * xref — Ultra blazing fast cross-references of an x86-64 ELF binary
 * Copyright (c) 2026 Alexander Panasenko
 *
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! `origin`: from an error message to the checks that build it. The message's `Display` arm gives
//! the variant index; the dispatch before the jump table gives the tag width and niche bias, so
//! the tag value is known. Every store of that value with that width is a candidate; it is a
//! site when its layout matches too (the tag offset of a non-stack object, or a payload next to
//! it). Nothing proves the object is that enum, so sites are shown with the pseudo-C conditions
//! guarding them for the reader to judge. A site in a jump-table arm reached unconditionally may
//! be a conversion from another enum's variant (`From<Inner> for Outer`): the inner variant is
//! traced the same way, as a hypothesis, and the site itself is kept. An input variant with the
//! same tag value and width (a clone, or another enum numbered alike) is noted, not re-traced.

mod dispatch;
mod guards;
mod passed;
mod stores;

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::ops::Range;

use iced_x86::FlowControl;

use crate::cli::hex_address;
use crate::commands::{Res, closest_arm, function};
use crate::image::Image;
use crate::locations::Location;
use crate::reach::{reach, windows};
use crate::runtime::RuntimeMap;
use crate::scan::{self, Query, decode};
use crate::tables::{Table, tables};
use dispatch::{Tag, tag_of};
use stores::{Store, stores};

pub struct OriginOptions {
    /// Accept text references this many bytes before the text (rustc fmt pieces).
    pub back: u64,
    /// Conversions followed from the message's enum inward.
    pub depth: usize,
    /// Sites rendered with their guards; the rest are listed.
    pub limit: usize,
    /// Print the backward slice of every rendered site.
    pub slice: bool,
    /// Calls a tag passed as an argument is followed through after the first callee.
    pub arg_depth: usize,
}

/// A `Display` arm naming the message: the variant indices of `table` in `function`.
struct DisplayArm {
    ip: u64,
    function: Range<u64>,
    dispatch: u64,
    base: u64,
    indices: Vec<usize>,
}

#[derive(Default)]
struct Counts {
    sites: usize,
    candidates: usize,
    conversions: usize,
    same_value: usize,
    rendered: usize,
    argument_sites: usize,
    argument_candidates: usize,
    readers: usize,
}

struct Tracer<'a> {
    image: &'a Image,
    locations: Vec<Location>,
    runtime: RuntimeMap,
    options: &'a OriginOptions,
    /// Searched tags: `(width, value, tag offset)` — the offset decides the layout evidence.
    seen: HashSet<(usize, u64, u64)>,
    /// Record kinds `(size, field offset)` whose element readers were listed.
    records: HashSet<(u64, u64)>,
    tables: HashMap<u64, Vec<Table>>,
    counts: Counts,
}

pub fn origin(image: &Image, target: &str, options: &OriginOptions, out: &mut dyn Write) -> Res {
    let arms = display_arms(image, target, options.back, out)?;
    let mut tracer = Tracer {
        image,
        locations: crate::locations::locations(image),
        runtime: RuntimeMap::detect(image),
        options,
        seen: HashSet::new(),
        records: HashSet::new(),
        tables: HashMap::new(),
        counts: Counts::default(),
    };
    for arm in &arms {
        let variants: Vec<String> = arm.indices.iter().map(|i| format!("{i} ({i:#x})")).collect();
        let tag = tag_of(image, &arm.function, arm.dispatch);
        writeln!(
            out,
            "display {:#x}  in {:#x}  variant {}  table {:#x}  {}",
            arm.ip,
            arm.function.start,
            variants.join(", "),
            arm.base,
            tag.map_or_else(|| format!("tag load not found before dispatch {:#x}", arm.dispatch), |t| describe(&t))
        )?;
        let Some(tag) = tag else { continue };
        for &index in &arm.indices {
            tracer.variant(&tag, index, 1, out)?;
        }
    }
    let c = &tracer.counts;
    writeln!(
        out,
        "{} layout-matching sites, {} stores without layout evidence, {} calls passing the tag to a store at \
         its offset or into a stack object ({} reads of it in a copy), {} calls passing it to a store of its width \
         elsewhere, {} possible conversions ({} from an input with the same tag value)",
        c.sites,
        c.candidates,
        c.argument_sites,
        c.readers,
        c.argument_candidates,
        c.conversions,
        c.same_value
    )?;
    writeln!(
        out,
        "sites are candidates: the store's value, width and layout match the tag; its guards show whether it is the check"
    )?;
    Ok(())
}

impl Tracer<'_> {
    fn variant(&mut self, tag: &Tag, index: usize, depth: usize, out: &mut dyn Write) -> Res {
        let pad = "  ".repeat(depth);
        let Some(value) = tag.value(index) else {
            writeln!(out, "{pad}variant {index} is the dataful variant: built by writing its payload, no tag store")?;
            return Ok(());
        };
        if !self.seen.insert((tag.width, value, tag.displacement)) {
            writeln!(out, "{pad}{} {value:#x} traced above", tag.type_name())?;
            return Ok(());
        }
        let found = stores(self.image, tag, value);
        writeln!(out, "{pad}{} stores of {} {value:#x}", found.len(), tag.type_name())?;
        let (mut conversions, mut candidates) = (Vec::new(), Vec::new());
        for store in found {
            if store.evidence.is_empty() {
                candidates.push(store);
                continue;
            }
            self.counts.sites += 1;
            self.site("site", &store, &pad, out)?;
            if let Some(from) = self.conversion(&store) {
                conversions.push((store, from));
            }
        }
        let (argument_sites, argument_candidates): (Vec<_>, Vec<_>) =
            passed::passed(self.image, tag, value, self.options.arg_depth).into_iter().partition(|p| p.layout);
        if !argument_sites.is_empty() {
            writeln!(
                out,
                "{pad}{} calls pass {} {value:#x} as an argument stored at the tag offset or into a stack object",
                argument_sites.len(),
                tag.type_name()
            )?;
        }
        for site in &argument_sites {
            self.counts.argument_sites += 1;
            self.site("argument site", &call_store(site), &pad, out)?;
            for reader in &site.readers {
                self.counts.readers += 1;
                self.site("  reader", &reader_store(site, reader), &pad, out)?;
            }
            self.element_readers(site, &pad, out)?;
        }
        for (store, (inner, base, indices)) in conversions {
            self.counts.conversions += 1;
            let variants: Vec<String> = indices.iter().map(|i| format!("{i} ({i:#x})")).collect();
            // A hypothesis: nothing ties the switch's object to the destination beyond the layout.
            writeln!(
                out,
                "{pad}possible conversion at {:#x}  in {:#x}: the arm of variant {} of table {base:#x} ({}) stores it \
                 unconditionally",
                store.ip,
                store.function.start,
                variants.join(", "),
                describe(&inner)
            )?;
            for index in indices {
                let same_layout = inner.width == tag.width && inner.displacement == tag.displacement;
                if same_layout && inner.value(index) == Some(value) {
                    // Equal value, width and tag offset say nothing about the input's enum: a
                    // clone of this enum, or another enum numbering the variant the same. Its
                    // stores and their evidence are the ones listed above, so they are not repeated.
                    // A different tag offset is another layout and is traced below.
                    self.counts.same_value += 1;
                    writeln!(
                        out,
                        "{pad}  input variant {index} has the same tag value and width ({} {value:#x}): \
                         a clone or another enum with the same numbering (unverified); its stores are listed above",
                        tag.type_name()
                    )?;
                } else if depth < self.options.depth {
                    self.variant(&inner, index, depth + 1, out)?;
                }
            }
        }
        if !candidates.is_empty() {
            writeln!(
                out,
                "{pad}{} stores without layout evidence (no tag offset of a non-stack object, no payload next to it): \
                 they may write an unrelated field holding the same number",
                candidates.len()
            )?;
        }
        for store in &candidates {
            self.counts.candidates += 1;
            self.site("candidate", store, &pad, out)?;
        }
        self.argument_candidates(&argument_candidates, tag, value, &pad, out)
    }

    /// Reads of the tag's field in records like the one the tag was copied into; several sites
    /// copying into the same kind of record share them, so they are listed once.
    fn element_readers(&mut self, site: &passed::Passed, pad: &str, out: &mut dyn Write) -> Res {
        let Some(copy) = &site.store.copy else { return Ok(()) };
        if site.element_readers.is_empty() || !self.records.insert((copy.size, copy.offset)) {
            return Ok(());
        }
        let capped = if site.element_readers.len() >= crate::callargs::records::MAX_READERS { " (the first ones)" } else { "" };
        writeln!(
            out,
            "{pad}  {} reads of +{:#x} of {:#x}-byte records{capped}: the element is found the same way (`imul reg, x, {:#x}`)",
            site.element_readers.len(),
            copy.offset,
            copy.size,
            copy.size
        )?;
        for reader in &site.element_readers {
            self.counts.readers += 1;
            let store = Store {
                ip: reader.ip,
                function: reader.function.clone(),
                text: reader.text.clone(),
                evidence: vec![format!("reads +{:#x} of a {:#x}-byte record", copy.offset, copy.size)],
            };
            self.site("  reader", &store, pad, out)?;
        }
        Ok(())
    }

    /// Calls passing the tag to a store at another offset: one line per callee argument and store,
    /// with the calls reaching it.
    fn argument_candidates(
        &mut self,
        found: &[passed::Passed],
        tag: &Tag,
        value: u64,
        pad: &str,
        out: &mut dyn Write,
    ) -> Res {
        if !found.is_empty() {
            writeln!(
                out,
                "{pad}{} calls pass {} {value:#x} to a function storing it with the tag's width into a field of an \
                 object other than the tag (a value handed on, or an unrelated one)",
                found.len(),
                tag.type_name()
            )?;
        }
        let mut grouped: Vec<(String, Vec<u64>)> = Vec::new();
        for passed in found {
            self.counts.argument_candidates += 1;
            let how = passed.describe();
            match grouped.iter_mut().find(|(known, _)| *known == how) {
                Some((_, ips)) => ips.push(passed.ip),
                None => grouped.push((how, vec![passed.ip])),
            }
        }
        for (how, ips) in grouped {
            let mut shown: Vec<String> = ips.iter().take(6).map(|ip| format!("{ip:#x}")).collect();
            if ips.len() > 6 {
                shown.push(format!("+{} more", ips.len() - 6));
            }
            writeln!(out, "{pad}argument candidate {}  {how}", shown.join(", "))?;
        }
        Ok(())
    }

    /// The jump-table arm that stores the tag unconditionally, when its dispatch decodes to an
    /// enum tag: `(inner tag, table, indices)`.
    fn conversion(&mut self, store: &Store) -> Option<(Tag, u64, Vec<usize>)> {
        let image = self.image;
        let found = self.tables.entry(store.function.start).or_insert_with(|| tables(image, &store.function));
        let (_, table, indices, arm) = closest_arm(found, store.ip)?;
        if !straight(image, arm, store.ip) {
            return None;
        }
        let inner = tag_of(image, &store.function, table.dispatch)?;
        Some((inner, table.base, indices))
    }

    fn site(&mut self, kind: &str, store: &Store, pad: &str, out: &mut dyn Write) -> Res {
        let evidence =
            if store.evidence.is_empty() { String::new() } else { format!("  [{}]", store.evidence.join(", ")) };
        writeln!(out, "{pad}{kind} {:#x}  in {:#x}  {}{evidence}", store.ip, store.function.start, store.text)?;
        if self.counts.rendered >= self.options.limit {
            return Ok(());
        }
        self.counts.rendered += 1;
        let options = crate::c::COptions { mark_ip: Some(store.ip), ..Default::default() };
        let c = match crate::c::c_one_options(self.image, &self.locations, &self.runtime, store.function.start, options)
        {
            Ok((_, c)) => c,
            Err(error) => {
                writeln!(out, "{pad}  (no pseudo-C: {error})")?;
                return Ok(());
            }
        };
        match guards::guarded(&c) {
            Some(found) => {
                for line in found.defs.iter().chain(&found.guards) {
                    writeln!(out, "{pad}  | {line}")?;
                }
                writeln!(out, "{pad}  > {}", found.statement)?;
                for line in &found.payload {
                    writeln!(out, "{pad}    {line}")?;
                }
            }
            None => {
                let what = if kind.trim_start() == "reader" { "read" } else { "store" };
                writeln!(out, "{pad}  (the {what} has no statement of its own in the pseudo-C)")?;
            }
        }
        if self.options.slice {
            crate::slice::slice_rendered_c(&store.function, &format!("{:#x}", store.ip), &[], &c, out)?;
        }
        Ok(())
    }
}

/// A read of the tag in the copy of a stack object, rendered with its guards.
fn reader_store(site: &passed::Passed, reader: &crate::callargs::pointer::Reader) -> Store {
    let offset = site.store.copy.as_ref().map_or(0, |copy| copy.offset);
    let via: Vec<String> = reader.via.iter().map(|(function, slot)| format!("{slot} to {function:#x}")).collect();
    let via = if via.is_empty() { String::new() } else { format!(", the copy passed as {}", via.join(", then as ")) };
    Store {
        ip: reader.ip,
        function: reader.function.clone(),
        text: reader.text.clone(),
        evidence: vec![format!("reads +{offset:#x} of the copy made at {:#x}{via}", site.store.copy.as_ref().map_or(0, |c| c.ip))],
    }
}

/// A call passing the tag, in the shape of a store so it renders with its guards.
fn call_store(passed: &passed::Passed) -> Store {
    let kind = if passed.tail { "jmp" } else { "call" };
    Store {
        ip: passed.ip,
        function: passed.function.clone(),
        text: format!("{kind} {:#x}", passed.callee),
        evidence: vec![passed.describe()],
    }
}

fn describe(tag: &Tag) -> String {
    use std::fmt::Write as _;
    let mut text = format!("tag {} [{:?}+{:#x}]", tag.type_name(), tag.base, tag.displacement).to_ascii_lowercase();
    if tag.bias != 0 {
        let _ = write!(text, " = index + {:#x}", tag.bias);
    }
    if let Some(dataful) = tag.dataful {
        let _ = write!(text, ", dataful index {dataful}");
    }
    text
}

/// The `Display` arms naming `target` (a text, or an address inside an arm).
fn display_arms(
    image: &Image,
    target: &str,
    back: u64,
    out: &mut dyn Write,
) -> Result<Vec<DisplayArm>, Box<dyn std::error::Error>> {
    let ips: Vec<u64> = if let Some(addr) = hex_address(target) {
        vec![addr]
    } else {
        let found = image.find(target.as_bytes());
        if found.is_empty() {
            return Err(format!("text {target:?} not found").into());
        }
        for at in &found {
            writeln!(out, "text {at:#x}  {target:?}")?;
        }
        let reach = reach(image, windows(&found, back));
        scan::search(image, &Query::Ref(reach.addresses)).into_iter().map(|hit| hit.ip).collect()
    };
    let mut arms = Vec::new();
    for ip in ips {
        let f = function(image, ip)?;
        let found = tables(image, &f);
        if let Some((_, table, indices, _)) = closest_arm(&found, ip) {
            arms.push(DisplayArm { ip, function: f, dispatch: table.dispatch, base: table.base, indices });
        } else {
            writeln!(out, "{ip:#x}  in {:#x}  no jump table", f.start)?;
        }
    }
    if arms.is_empty() {
        return Err(format!("no jump-table arm names {target:?}").into());
    }
    Ok(arms)
}

/// No branch, jump or return between `from` and `to`: the arm reaches the store unconditionally.
fn straight(image: &Image, from: u64, to: u64) -> bool {
    let Some(bytes) = image.code(&(from..to)) else { return false };
    let mut plain = true;
    decode(bytes, from, |ins| {
        plain &= matches!(ins.flow_control(), FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall);
    });
    plain
}

#[cfg(test)]
mod tests;
