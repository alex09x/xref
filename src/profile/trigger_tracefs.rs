/*
 * XRef — filtered tracefs trigger for sampling windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use crate::live::probe::tracefs_cleanup::{
    CleanupSupervisor, append_tracefs_line, discover_tracefs_root, teardown_session_resources,
};
use std::{
    fmt::Write as _,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// One private tracepoint shared by the per-thread perf samplers.
pub(super) struct Registration {
    pub(super) id: u64,
    root: PathBuf,
    instance: String,
    event: String,
    registered: bool,
    supervisor: Option<CleanupSupervisor>,
    filters: Vec<crate::live::ProfileValueFilter>,
    fields: Vec<(String, usize, usize)>,
}

impl Registration {
    pub(super) fn new(pid: u32, offset: u64, fetch_specs: &[String], filter_specs: &[String]) -> Result<Self, String> {
        let fetches = crate::live::parse_profile_fetches(fetch_specs)?;
        let names = fetches.iter().map(|fetch| fetch.name.clone()).collect::<Vec<_>>();
        let filters = crate::live::parse_profile_filters(filter_specs, false, &names)?;
        let root = discover_tracefs_root();
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_nanos());
        let group = format!("xpf_{}_{:x}_{:x}", std::process::id(), nonce, NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let event = format!("{group}/trigger");
        let instance = format!("xref_{group}");
        let supervisor = CleanupSupervisor::spawn(&root, &instance, std::slice::from_ref(&event))
            .ok_or("cannot start tracefs trigger cleanup watchdog")?;
        let mut registration = Self {
            id: 0,
            root,
            instance,
            event,
            registered: false,
            supervisor: Some(supervisor),
            filters,
            fields: Vec::new(),
        };
        let mut fields = String::new();
        for fetch in &fetches {
            write!(&mut fields, " {}={}", fetch.name, fetch.expression).map_err(|_| "format trigger fetch")?;
        }
        let definition = format!("p:{} /proc/{pid}/exe:{offset:#x}{fields}\n", registration.event);
        append_tracefs_line(&registration.root.join("uprobe_events"), &definition, "register profile trigger")?;
        registration.registered = true;
        let directory = registration.root.join("events").join(&group).join("trigger");
        let format = std::fs::read_to_string(directory.join("format"))
            .map_err(|error| format!("read profile trigger format: {error}"))?;
        registration.fields = parse_fields(&format, &names)?;
        registration.id = std::fs::read_to_string(directory.join("id"))
            .map_err(|error| format!("read profile trigger tracepoint id: {error}"))?
            .trim()
            .parse()
            .map_err(|_| "invalid profile trigger tracepoint id")?;
        Ok(registration)
    }

    pub(super) fn accepts(&self, raw: &[u8]) -> Result<bool, String> {
        for filter in &self.filters {
            let (_, offset, size) =
                self.fields.iter().find(|(name, _, _)| name == &filter.field).ok_or("missing trigger filter field")?;
            let bytes = raw
                .get(*offset..offset.checked_add(*size).ok_or("trigger field overflow")?)
                .ok_or("truncated trigger field")?;
            let mut value = [0_u8; 8];
            value[..*size].copy_from_slice(bytes);
            if !filter.op.test(u64::from_le_bytes(value), filter.value) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn parse_fields(format: &str, names: &[String]) -> Result<Vec<(String, usize, usize)>, String> {
    let mut result = Vec::with_capacity(names.len());
    for name in names {
        let line = format
            .lines()
            .find(|line| {
                line.split(';').next().and_then(|field| field.split_whitespace().last()) == Some(name.as_str())
            })
            .ok_or_else(|| format!("trigger field {name:?} absent from tracepoint format"))?;
        let parse = |key: &str| -> Result<usize, String> {
            line.split(';')
                .find_map(|part| part.trim().strip_prefix(key))
                .ok_or_else(|| format!("missing {key} in trigger format"))?
                .trim()
                .parse()
                .map_err(|_| format!("invalid {key} in trigger format"))
        };
        let offset = parse("offset:")?;
        let size = parse("size:")?;
        if !matches!(size, 1 | 2 | 4 | 8) || offset.checked_add(size).is_none() {
            return Err("unsupported trigger field size".into());
        }
        result.push((name.clone(), offset, size));
    }
    Ok(result)
}

impl Drop for Registration {
    fn drop(&mut self) {
        if self.registered {
            let instance = self.root.join("instances").join(&self.instance);
            for warning in
                teardown_session_resources(&self.root, &instance, std::slice::from_ref(&self.event), None, None)
            {
                eprintln!("{warning}");
            }
        }
        if let Some(supervisor) = &mut self.supervisor {
            supervisor.disarm_and_wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracepoint_fields_are_bounded_and_required() -> Result<(), String> {
        let format = "field:unsigned short common_type; offset:0; size:2; signed:0;\nfield:u64 op; offset:16; size:8; signed:0;\n";
        assert_eq!(parse_fields(format, &["op".into()])?, [("op".into(), 16, 8)]);
        assert!(parse_fields(format, &["missing".into()]).is_err());
        assert!(parse_fields("field:u64 op; offset:16; size:16;", &["op".into()]).is_err());
        Ok(())
    }
}
