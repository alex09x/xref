/*
 * XRef — bounded Intel PT mapping validation
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

const MAX_MAPPINGS: usize = 4096;

/// Validate per-mapping file identity in addition to the global build-ID
/// feature. A path may be reused for a different inode during a recording.
pub(super) fn file_identity(
    previous: &mut Option<linux_perf_data::linux_perf_event_reader::Mmap2FileId>,
    current: &linux_perf_data::linux_perf_event_reader::Mmap2FileId,
    build_id: &[u8],
) -> Result<(), &'static str> {
    use linux_perf_data::linux_perf_event_reader::Mmap2FileId;
    match current {
        Mmap2FileId::BuildId(value) if value.is_empty() || value.as_slice() != build_id => {
            return Err("PT mapping build ID mismatch");
        }
        Mmap2FileId::InodeAndVersion(value) if value.inode == 0 => return Err("PT mapping has no inode identity"),
        _ => {}
    }
    if previous.as_ref().is_some_and(|value| value != current) {
        return Err("PT target file identity changed");
    }
    if previous.is_none() {
        *previous = Some(current.clone());
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct Mappings {
    target: Vec<(u64, u64)>,
    other: Vec<(u64, u64)>,
}

impl Mappings {
    pub(super) fn add(&mut self, start: u64, length: u64, target: bool) -> Result<(), &'static str> {
        let end = start.checked_add(length).ok_or("mapping range overflow")?;
        if length == 0 {
            return Err("empty mapping");
        }
        if self.target.len().saturating_add(self.other.len()) >= MAX_MAPPINGS {
            return Err("PT mapping budget exceeded");
        }
        let overlaps = |&(other_start, other_end): &(u64, u64)| start < other_end && end > other_start;
        if target {
            if self.target.iter().any(overlaps) || self.other.iter().any(overlaps) {
                return Err("overlapping PT target mapping");
            }
            self.target.push((start, end));
        } else {
            if self.target.iter().any(overlaps) {
                return Err("PT target mapping replaced");
            }
            self.other.push((start, end));
        }
        Ok(())
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.target.is_empty()
    }

    pub(super) fn contains(&self, address: u64) -> bool {
        self.target.iter().any(|&(start, end)| address >= start && address < end)
    }
}

#[cfg(test)]
mod tests {
    use super::Mappings;

    #[test]
    fn rejects_overlap_in_either_order_and_wraparound() -> Result<(), &'static str> {
        let mut first = Mappings::default();
        first.add(0x1000, 0x100, true)?;
        assert!(first.contains(0x1000));
        assert!(!first.contains(0x1100));
        assert!(first.add(0x1080, 0x100, false).is_err());
        assert!(first.add(0x1080, 0x100, true).is_err());
        assert!(first.add(u64::MAX, 2, false).is_err());
        let mut second = Mappings::default();
        second.add(0x1080, 0x100, false)?;
        assert!(second.add(0x1000, 0x100, true).is_err());
        second.add(0x3000, 0x100, true)?;
        Ok(())
    }

    #[test]
    fn rejects_mmap_build_id_and_inode_reuse() -> Result<(), &'static str> {
        use linux_perf_data::linux_perf_event_reader::{Mmap2FileId, Mmap2InodeAndVersion};
        let mut identity = None;
        let first =
            Mmap2FileId::InodeAndVersion(Mmap2InodeAndVersion { major: 8, minor: 1, inode: 7, inode_generation: 1 });
        super::file_identity(&mut identity, &first, &[1, 2])?;
        let changed =
            Mmap2FileId::InodeAndVersion(Mmap2InodeAndVersion { major: 8, minor: 1, inode: 8, inode_generation: 1 });
        assert!(super::file_identity(&mut identity, &changed, &[1, 2]).is_err(), "same path can name another inode");
        let mut identity = None;
        assert!(super::file_identity(&mut identity, &Mmap2FileId::BuildId(vec![1, 3]), &[1, 2]).is_err());
        super::file_identity(&mut identity, &Mmap2FileId::BuildId(vec![1, 2]), &[1, 2])?;
        Ok(())
    }
}
