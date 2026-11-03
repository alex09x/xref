/*
 * XRef Code — evidence-producing binary analysis
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::Collected;
use super::util::{Cursor, add, bytes};
use std::collections::BTreeSet;

pub(super) fn collect(trie: &[u8], image_base: u64, out: &mut Collected) -> Result<(), String> {
    let mut active = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![(0usize, false)];
    while let Some((offset, exit)) = stack.pop() {
        if exit {
            active.remove(&offset);
            continue;
        }
        if active.contains(&offset) {
            return Err("Mach-O export trie cycle".into());
        }
        if !visited.insert(offset) {
            continue;
        }
        out.charge(1)?;
        if visited.len() > 1_000_000 {
            return Err("Mach-O export trie node budget exceeded".into());
        }
        active.insert(offset);
        stack.push((offset, true));
        let mut cur = Cursor::at(trie, offset)?;
        let terminal_size = usize::try_from(cur.uleb()?).map_err(|_| "Mach-O export terminal overflow")?;
        let terminal = bytes(trie, cur.pos, terminal_size)?;
        if !terminal.is_empty() {
            let mut value = Cursor::new(terminal);
            let flags = value.uleb()?;
            let unsupported = flags & !0x1f != 0 || flags & 3 == 3;
            if unsupported {
                out.exports_complete = false;
                out.warning("Unsupported Mach-O export flags");
            } else if flags & 8 != 0 {
                value.uleb()?;
                value.cstr()?;
            } else {
                let address = value.uleb()?;
                out.exports.insert(if flags & 3 == 2 { address } else { add(image_base, address)? });
                if flags & 0x10 != 0 {
                    out.exports.insert(add(image_base, value.uleb()?)?);
                }
            }
            if !unsupported && value.pos != terminal.len() {
                return Err("Mach-O export terminal has trailing data".into());
            }
        }
        cur.pos = cur.pos.checked_add(terminal_size).ok_or("Mach-O export terminal overflow")?;
        let children = cur.byte()?;
        let mut pending = vec![];
        for _ in 0..children {
            cur.cstr()?;
            let child = usize::try_from(cur.uleb()?).map_err(|_| "Mach-O export child offset overflow")?;
            if child >= trie.len() {
                return Err("Mach-O export child out of bounds".into());
            }
            pending.push((child, false));
        }
        stack.extend(pending.into_iter().rev());
    }
    Ok(())
}
