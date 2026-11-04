/*
 * XRef — Bounded folded-stack aggregation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use super::models::SymbolizedFrame;
use std::collections::BTreeMap;

const MAX_GROUPS: usize = 8192;
const MAX_KEY_BYTES: usize = 8192;
const MAX_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub struct FoldedGroups {
    pub groups: BTreeMap<String, u64>,
    pub truncated: bool,
    key_bytes: usize,
}

impl FoldedGroups {
    pub fn add(&mut self, frames: &[SymbolizedFrame], weight: u64, callers: bool) -> Result<(), String> {
        let key = frames
            .iter()
            .enumerate()
            .rev()
            .map(|(position, frame)| match &frame.function {
                Some(function) if callers && position > 0 => {
                    format!("{}@{}", function.label, frame.call_site.as_deref().unwrap_or("unknown_call_site"))
                }
                Some(function) => function.label.clone(),
                None => "[unknown_or_outside_target]".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(";");
        self.insert(key, weight)
    }

    pub fn add_caller(&mut self, frames: &[SymbolizedFrame], weight: u64) -> Result<(), String> {
        let caller = frames.get(1);
        let key = caller.and_then(|frame| frame.function.as_ref()).map_or_else(
            || "[unknown_immediate_caller]".to_owned(),
            |function| {
                format!(
                    "{}@{}",
                    function.label,
                    caller.and_then(|frame| frame.call_site.as_deref()).unwrap_or("unknown_call_site")
                )
            },
        );
        self.insert(key, weight)
    }

    fn insert(&mut self, key: String, weight: u64) -> Result<(), String> {
        if !self.groups.contains_key(&key) {
            if key.len() > MAX_KEY_BYTES
                || self.groups.len() >= MAX_GROUPS
                || self.key_bytes.saturating_add(key.len()) > MAX_AGGREGATE_BYTES
            {
                self.truncated = true;
                return Ok(());
            }
            self.key_bytes += key.len();
        }
        let count = self.groups.entry(key).or_default();
        *count = count.checked_add(weight).ok_or("folded sample count overflow")?;
        Ok(())
    }
}
