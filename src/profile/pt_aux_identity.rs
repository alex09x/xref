/*
 * XRef — Intel PT AUX identity checks
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#[cfg(test)]
use std::collections::BTreeSet;

/// Tracks only thread identities proven to belong to the selected process.
/// AUX data tagged with an unknown thread or a per-CPU wildcard must not be
/// attributed to that process without additional scheduler sideband.
#[cfg(test)]
pub(super) struct Threads {
    pid: u32,
    alive: bool,
    last_timestamp: u64,
    tids: BTreeSet<u32>,
}

#[cfg(test)]
impl Threads {
    pub(super) fn new(pid: u32) -> Result<Self, &'static str> {
        if pid == 0 {
            return Err("invalid target PID");
        }
        Ok(Self { pid, alive: true, last_timestamp: 0, tids: BTreeSet::from([pid]) })
    }

    /// Sideband without a usable ordered timestamp cannot prove which mapping
    /// or thread owned a later AUX span.
    pub(super) fn advance(&mut self, timestamp: u64) -> Result<(), &'static str> {
        if !self.alive {
            return Err("target process identity ended");
        }
        if timestamp == 0 || timestamp < self.last_timestamp {
            self.invalidate();
            return Err("missing or unordered sideband timestamp");
        }
        self.last_timestamp = timestamp;
        Ok(())
    }

    pub(super) fn invalidate(&mut self) {
        self.alive = false;
        self.tids.clear();
    }

    pub(super) fn fork(&mut self, pid: u32, tid: u32) -> Result<(), &'static str> {
        if !self.alive {
            return Err("target process identity ended");
        }
        if pid == self.pid {
            if tid == 0 || tid == u32::MAX {
                return Err("invalid thread ID");
            }
            self.tids.insert(tid);
        }
        Ok(())
    }

    pub(super) fn exit(&mut self, pid: u32, tid: u32) {
        if pid == self.pid {
            self.tids.remove(&tid);
            if tid == self.pid {
                self.alive = false;
                self.tids.clear();
            }
        }
    }

    pub(super) fn exec(&mut self, pid: u32) {
        if pid == self.pid {
            self.invalidate();
        }
    }

    pub(super) fn accepts(&self, tid: u32) -> bool {
        self.alive && self.last_timestamp != 0 && tid != 0 && tid != u32::MAX && self.tids.contains(&tid)
    }
}

/// `PERF_RECORD_AUXTRACE_INFO` starts with a little-endian type and reserved
/// word. Type one denotes Intel PT; other AUX producers are not PT streams.
pub(super) fn intel_pt_info(data: &[u8]) -> Result<bool, &'static str> {
    let header = data.get(..8).ok_or("truncated AUXTRACE_INFO")?;
    let kind = u32::from_le_bytes(header[..4].try_into().map_err(|_| "invalid AUXTRACE_INFO")?);
    let reserved = u32::from_le_bytes(header[4..].try_into().map_err(|_| "invalid AUXTRACE_INFO")?);
    if reserved != 0 {
        return Err("invalid AUXTRACE_INFO reserved field");
    }
    Ok(kind == 1)
}

/// A missing recorded or local build ID is not evidence that instruction
/// bytes in the selected executable correspond to the recorded PT stream.
/// Matching IDs do not prove the runtime mapping or its bytes were unchanged.
pub(super) fn verified_build_id(recorded: Option<&[u8]>, local: Option<&[u8]>) -> bool {
    matches!((recorded, local), (Some(left), Some(right)) if !left.is_empty() && left == right)
}

/// Check the recorded executable mapping against the supplied ELF layout and
/// slide. This validates address arithmetic only; a build ID and sideband are
/// still needed, and neither proves that live bytes were unmodified.
pub(super) fn mapping_matches(
    mapping: &super::types::Mapping,
    image: &crate::image::Image,
    pid: u32,
    slide: i64,
) -> bool {
    if mapping.pid != pid
        || !mapping.executable
        || mapping.length == 0
        || mapping.start.checked_add(mapping.length).is_none()
    {
        return false;
    }
    let mut matches = 0;
    for segment in &image.segments {
        let Ok(offset) = u64::try_from(segment.offset) else {
            continue;
        };
        let Ok(size) = u64::try_from(segment.size) else {
            continue;
        };
        let Some(relative) = mapping.file_offset.checked_sub(offset) else {
            continue;
        };
        if relative >= size {
            continue;
        }
        let Some(static_start) = segment.va.checked_add(relative) else {
            continue;
        };
        let runtime = if slide >= 0 {
            static_start.checked_add(slide.unsigned_abs())
        } else {
            static_start.checked_sub(slide.unsigned_abs())
        };
        if runtime != Some(mapping.start) {
            continue;
        }
        let covered = mapping.length.min(size - relative);
        let Some(static_end) = static_start.checked_add(covered) else {
            continue;
        };
        if image.functions.iter().any(|function| function.start < static_end && function.end > static_start) {
            matches += 1;
        }
    }
    matches == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_recorded_mapping_against_elf_slide() {
        let image = crate::image::Image {
            segments: vec![crate::image::Segment { va: 0x1000, offset: 0x1000, size: 0x1000 }],
            functions: std::iter::once(0x1100..0x1200).collect(),
            ..crate::image::Image::default()
        };
        let mut mapping = super::super::types::Mapping {
            timestamp_ns: 1,
            pid: 42,
            tid: 42,
            start: 0x0050_1000,
            length: 0x1000,
            file_offset: 0x1000,
            device_major: 0,
            device_minor: 0,
            inode: 1,
            executable: true,
            sha256: None,
            path: "/target".into(),
        };
        assert!(mapping_matches(&mapping, &image, 42, 0x0050_0000));
        assert!(!mapping_matches(&mapping, &image, 42, 0x0040_0000), "wrong slide must fail");
        mapping.file_offset = 0x2000;
        assert!(!mapping_matches(&mapping, &image, 42, 0x0050_0000), "wrong file offset must fail");
        mapping.file_offset = 0x1000;
        mapping.pid = 43;
        assert!(!mapping_matches(&mapping, &image, 42, 0x0050_0000), "wrong PID must fail");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn distinguishes_two_real_elf_build_ids() -> Result<(), Box<dyn std::error::Error>> {
        use object::Object;
        use std::process::Command;
        let dir = tempfile::tempdir()?;
        let mut ids = Vec::new();
        for value in [1, 2] {
            let source = dir.path().join(format!("target-{value}.c"));
            let binary = dir.path().join(format!("target-{value}"));
            std::fs::write(&source, format!("int main(void) {{ return {value}; }}\n"))?;
            let status = Command::new("cc").arg("-Wl,--build-id").arg(&source).arg("-o").arg(&binary).status()?;
            assert!(status.success(), "ELF fixture compilation failed");
            let bytes = std::fs::read(binary)?;
            let object = object::File::parse(bytes.as_slice())?;
            ids.push(object.build_id()?.ok_or("fixture has no build ID")?.to_vec());
        }
        assert!(verified_build_id(Some(&ids[0]), Some(&ids[0])));
        assert!(!verified_build_id(Some(&ids[0]), Some(&ids[1])), "different compiled ELFs must not match");
        assert!(!verified_build_id(Some(&ids[0]), None), "missing identity must not match");
        Ok(())
    }

    #[test]
    fn excludes_unknown_threads_reuse_and_other_aux_types() -> Result<(), &'static str> {
        let mut target = Threads::new(42)?;
        assert!(!target.accepts(42), "missing sideband timestamp cannot prove ownership");
        target.advance(1)?;
        assert!(target.accepts(42));
        assert!(!target.accepts(u32::MAX), "CPU-wide trace requires scheduler sideband");
        assert!(!target.accepts(43), "thread must be established by a fork event");
        target.fork(42, 43)?;
        assert!(target.accepts(43));
        target.exit(42, 43);
        assert!(!target.accepts(43));
        target.fork(42, 43)?;
        target.exec(42);
        assert!(!target.accepts(42));
        assert!(!target.accepts(43));
        assert!(target.fork(42, 43).is_err(), "exec ends the pinned identity");
        assert!(intel_pt_info(&[1, 0, 0, 0, 0, 0, 0, 0])?);
        assert!(!intel_pt_info(&[2, 0, 0, 0, 0, 0, 0, 0])?);
        assert!(intel_pt_info(&[1]).is_err());
        assert!(verified_build_id(Some(&[1, 2]), Some(&[1, 2])));
        assert!(!verified_build_id(None, Some(&[1, 2])), "missing recorded identity cannot be verified");
        assert!(!verified_build_id(Some(&[1, 2]), None), "missing local identity cannot be verified");
        assert!(!verified_build_id(Some(&[]), Some(&[])), "empty IDs are not identities");
        assert!(!verified_build_id(Some(&[1, 2]), Some(&[1, 3])), "different builds must not be matched");
        let mut unordered = Threads::new(42)?;
        unordered.advance(10)?;
        assert!(unordered.advance(9).is_err(), "out-of-order sideband must fail");
        assert!(!unordered.accepts(42), "out-of-order sideband invalidates ownership");
        let mut lost = Threads::new(42)?;
        lost.advance(10)?;
        lost.invalidate();
        assert!(!lost.accepts(42), "lost sideband invalidates ownership");
        let mut missing = Threads::new(42)?;
        assert!(missing.advance(0).is_err(), "missing timestamps cannot prove ordering");
        assert!(!missing.accepts(42));
        Ok(())
    }
}
