/*
 * XRef — Rendering of tags passed as call arguments, and of the reads of their copies
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::io::Write;

use super::Tracer;
use super::dispatch::Tag;
use super::passed::Passed;
use super::stores::Store;
use crate::callargs::pointer::Reader;
use crate::callargs::records::MAX_READERS;
use crate::commands::Res;

impl Tracer<'_> {
    /// The calls passing the tag to a store at its offset or into a stack object, each with the
    /// reads of the tag in the copy of that object.
    pub(super) fn argument_sites(
        &mut self,
        sites: &[Passed],
        tag: &Tag,
        value: u64,
        pad: &str,
        out: &mut dyn Write,
    ) -> Res {
        if !sites.is_empty() {
            writeln!(
                out,
                "{pad}{} calls pass {} {value:#x} as an argument stored at the tag offset or into a stack object",
                sites.len(),
                tag.type_name()
            )?;
        }
        for site in sites {
            self.counts.argument_sites += 1;
            self.site("argument site", &call_store(site), pad, out)?;
            for reader in &site.readers {
                self.counts.readers += 1;
                self.site("  reader", &reader_store(site, reader), pad, out)?;
            }
            self.element_readers(site, pad, out)?;
        }
        Ok(())
    }

    /// Reads of the tag's field in records like the one the tag was copied into; several sites
    /// copying into the same kind of record share them, so they are listed once.
    fn element_readers(&mut self, site: &Passed, pad: &str, out: &mut dyn Write) -> Res {
        let Some(copy) = &site.store.copy else { return Ok(()) };
        if site.element_readers.is_empty() || !self.records.insert((copy.size, copy.offset)) {
            return Ok(());
        }
        let capped = if site.element_readers.len() >= MAX_READERS { " (the first ones)" } else { "" };
        writeln!(
            out,
            "{pad}  {} reads of +{:#x} of {:#x}-byte records{capped}: the element comes from the record size (an \
             index scaled by it, a pointer stepped by it)",
            site.element_readers.len(),
            copy.offset,
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
    pub(super) fn argument_candidates(
        &mut self,
        found: &[Passed],
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
}

/// A read of the tag in the copy of a stack object, rendered with its guards.
fn reader_store(site: &Passed, reader: &Reader) -> Store {
    let (offset, copied_at) = site.store.copy.as_ref().map_or((0, 0), |copy| (copy.offset, copy.ip));
    let via: Vec<String> = reader.via.iter().map(|(function, slot)| format!("{slot} to {function:#x}")).collect();
    let via = if via.is_empty() { String::new() } else { format!(", the copy passed as {}", via.join(", then as ")) };
    Store {
        ip: reader.ip,
        function: reader.function.clone(),
        text: reader.text.clone(),
        evidence: vec![format!("reads +{offset:#x} of the copy made at {copied_at:#x}{via}")],
    }
}

/// A call passing the tag, in the shape of a store so it renders with its guards.
fn call_store(passed: &Passed) -> Store {
    let kind = if passed.tail { "jmp" } else { "call" };
    Store {
        ip: passed.ip,
        function: passed.function.clone(),
        text: format!("{kind} {:#x}", passed.callee),
        evidence: vec![passed.describe()],
    }
}
