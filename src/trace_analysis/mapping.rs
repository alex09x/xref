/*
 * XRef — Process-scoped trace mapping and build identity checks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

use std::collections::{BTreeMap, BTreeSet};

use super::{
    index::{RuntimeMapping, SymbolIndex},
    parse::{MmapRecord, RawSample},
};

pub const MAX_MAPPINGS: usize = 32768;
const MAX_PROCESSES: usize = 4096;
const MAX_THREADS: usize = 65536;

#[derive(Clone, Debug, Default)]
pub struct MappingState {
    pub explicit: Vec<RuntimeMapping>,
    dynamic: BTreeMap<u32, Vec<RuntimeMapping>>,
    seen_mmap: BTreeSet<u32>,
    thread_groups: BTreeMap<u32, u32>,
    explicit_pid: Option<u32>,
    mapping_count: usize,
}

fn normalized_path(path: &str) -> &str {
    path.trim().strip_suffix(" (deleted)").unwrap_or_else(|| path.trim())
}

impl MappingState {
    pub fn with_explicit(explicit: Vec<RuntimeMapping>) -> Self {
        Self { explicit, ..Self::default() }
    }

    fn metadata_room(&self, pid: u32, tid: u32) -> Result<(), String> {
        if self.seen_mmap.len() >= MAX_PROCESSES && !self.seen_mmap.contains(&pid) {
            return Err("trace process-mapping budget exhausted".to_owned());
        }
        if self.thread_groups.len() >= MAX_THREADS && !self.thread_groups.contains_key(&tid) {
            return Err("trace thread metadata budget exhausted".to_owned());
        }
        Ok(())
    }

    pub fn mmap(&mut self, index: &SymbolIndex, event: &MmapRecord, target_path: Option<&str>) -> Result<(), String> {
        self.metadata_room(event.pid, event.tid)?;
        self.seen_mmap.insert(event.pid);
        self.thread_groups.insert(event.tid, event.pid);
        let end = event.start.checked_add(event.len).ok_or("mapping end overflow")?;
        let mappings = self.dynamic.entry(event.pid).or_default();
        // A foreign/replacement mapping must invalidate an older target range.
        let old_len = mappings.len();
        mappings.retain(|mapping| mapping.end <= event.start || end <= mapping.start);
        self.mapping_count -= old_len - mappings.len();
        let path_matches = target_path.is_some_and(|path| normalized_path(path) == normalized_path(&event.path));
        let build_matches = event
            .build_id
            .as_deref()
            .zip(index.identity.build_id.as_deref())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
        if !path_matches && !build_matches {
            return Ok(());
        }
        if event.build_id.is_some() {
            index.validate_identity(event.build_id.as_deref())?;
        }
        if event.executable {
            if self.mapping_count >= MAX_MAPPINGS {
                return Err("trace active-mapping budget exhausted".to_owned());
            }
            let evidence = if event.build_id.is_some() {
                "mmap_build_id_matches_selected_image"
            } else {
                "mmap_path_matches_selected_image_build_id_unavailable"
            };
            mappings.push(index.mapping_from_file_offset(
                event.start,
                event.len,
                event.offset,
                Some(event.pid),
                true,
                evidence,
            )?);
            self.mapping_count += 1;
        }
        Ok(())
    }

    #[allow(clippy::similar_names)] // PID/TID and parent PID/TID are distinct perf ABI fields.
    pub fn fork(&mut self, pid: u32, tid: u32, parent_pid: u32, parent_tid: u32) -> Result<(), String> {
        self.metadata_room(parent_pid, parent_tid)?;
        self.thread_groups.insert(parent_tid, parent_pid);
        self.metadata_room(pid, tid)?;
        self.thread_groups.insert(tid, pid);
        if pid != parent_pid {
            self.mapping_count -= self.dynamic.remove(&pid).map_or(0, |old| old.len());
            if self
                .dynamic
                .get(&parent_pid)
                .is_some_and(|maps| self.mapping_count.saturating_add(maps.len()) > MAX_MAPPINGS)
            {
                return Err("trace inherited-mapping budget exhausted".to_owned());
            }
            if let Some(parent) = self.dynamic.get(&parent_pid).cloned() {
                let inherited = parent
                    .into_iter()
                    .map(|mut mapping| {
                        mapping.pid = Some(pid);
                        let inherited_evidence = if mapping.evidence == "mmap_build_id_matches_selected_image"
                            || mapping.evidence == "fork_inherited_build_id_matched_mapping"
                        {
                            "fork_inherited_build_id_matched_mapping"
                        } else {
                            "fork_inherited_mapping_not_new_exec_identity_proof"
                        };
                        inherited_evidence.clone_into(&mut mapping.evidence);
                        mapping
                    })
                    .collect();
                let inherited: Vec<_> = inherited;
                self.mapping_count += inherited.len();
                self.mapping_count -= self.dynamic.insert(pid, inherited).map_or(0, |old| old.len());
            }
            if self.seen_mmap.contains(&parent_pid) {
                self.seen_mmap.insert(pid);
            }
        }
        Ok(())
    }

    pub fn exec(&mut self, pid: u32) -> Result<(), String> {
        self.metadata_room(pid, pid)?;
        self.mapping_count -= self.dynamic.remove(&pid).map_or(0, |old| old.len());
        self.seen_mmap.insert(pid);
        self.thread_groups.retain(|_, tgid| *tgid != pid);
        self.thread_groups.insert(pid, pid);
        Ok(())
    }

    pub fn sample_pid(&self, sample: &RawSample) -> Option<u32> {
        if sample.pid_explicit {
            sample.pid
        } else {
            sample.tid.and_then(|tid| self.thread_groups.get(&tid).copied()).or(sample.pid)
        }
    }

    pub fn for_sample(&mut self, pid: Option<u32>, selected_pid: Option<u32>) -> Result<&[RuntimeMapping], String> {
        if let Some(pid) = pid {
            if self.seen_mmap.contains(&pid) {
                return Ok(self.dynamic.get(&pid).map_or(&[], Vec::as_slice));
            }
            if !self.explicit.is_empty() && selected_pid.is_none() {
                if self.explicit_pid.is_some_and(|first| first != pid) {
                    return Err(
                        "multiple processes with a single explicit mapping: specify --pid and perf PID/TID fields"
                            .to_owned(),
                    );
                }
                self.explicit_pid = Some(pid);
            }
        }
        Ok(&self.explicit)
    }

    pub fn set_proc_maps(&mut self, index: &SymbolIndex, text: &str, target_path: &str) -> Result<(), String> {
        let mut mappings = Vec::new();
        for line in text.lines() {
            let mut columns = line.split_whitespace();
            let (Some(range), Some(permissions), Some(offset), Some(_dev), Some(_inode)) =
                (columns.next(), columns.next(), columns.next(), columns.next(), columns.next())
            else {
                continue;
            };
            let path = columns.collect::<Vec<_>>().join(" ");
            if normalized_path(&path) != normalized_path(target_path) || !permissions.contains('x') {
                continue;
            }
            let (start, end) = range.split_once('-').ok_or("invalid proc maps range")?;
            let (start, end, offset) =
                (super::index::parse_hex(start)?, super::index::parse_hex(end)?, super::index::parse_hex(offset)?);
            let len = end.checked_sub(start).filter(|len| *len > 0).ok_or("invalid proc maps range")?;
            if mappings.len() >= MAX_MAPPINGS {
                return Err("proc maps snapshot mapping budget exhausted".to_owned());
            }
            mappings.push(index.mapping_from_file_offset(
                start,
                len,
                offset,
                None,
                true,
                "caller_supplied_proc_maps_snapshot",
            )?);
        }
        if mappings.is_empty() {
            return Err(
                "no executable mapping for selected path; specify the original runtime --target-path".to_owned()
            );
        }
        self.explicit = mappings;
        Ok(())
    }
}
