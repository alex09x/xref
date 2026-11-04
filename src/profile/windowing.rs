/*
 * XRef — bounded profiler trigger windows
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

/// Windows are half-open and numbered in trigger-time order from one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Window {
    pub(super) trigger_ns: u64,
    pub(super) end_ns: u64,
}

impl Window {
    #[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
    pub(super) fn new(trigger_ns: u64, duration_ns: u64) -> Result<Self, &'static str> {
        if duration_ns == 0 {
            return Err("trigger window must be positive");
        }
        Ok(Self { trigger_ns, end_ns: trigger_ns.checked_add(duration_ns).ok_or("trigger window timestamp overflow")? })
    }

    pub(super) const fn contains(self, timestamp_ns: u64) -> bool {
        self.trigger_ns <= timestamp_ns && timestamp_ns < self.end_ns
    }
}

/// Index interval unions once so report time is logarithmic in window count.
pub(super) struct WindowIndex<'a> {
    windows: &'a [Window],
    prefix_end: Vec<u64>,
    selected: Option<usize>,
}

impl<'a> WindowIndex<'a> {
    pub(super) fn new(windows: &'a [Window], selected: Option<usize>) -> Result<Self, &'static str> {
        let selected = selected.map(|index| index.checked_sub(1).ok_or("window numbers start at one")).transpose()?;
        if selected.is_some_and(|index| index >= windows.len()) {
            return Err("window number exceeds captured windows");
        }
        let mut largest = 0;
        let prefix_end = windows
            .iter()
            .map(|window| {
                largest = largest.max(window.end_ns);
                largest
            })
            .collect();
        Ok(Self { windows, prefix_end, selected })
    }

    pub(super) fn contains(&self, timestamp_ns: u64) -> bool {
        if let Some(index) = self.selected {
            return self.windows[index].contains(timestamp_ns);
        }
        let count = self.windows.partition_point(|window| window.trigger_ns <= timestamp_ns);
        count > 0 && self.prefix_end[count - 1] > timestamp_ns
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct CaptureWindows {
    pub(super) windows: Vec<Window>,
    max_windows: usize,
    duration: std::time::Duration,
    deadline: Option<std::time::Instant>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl CaptureWindows {
    pub(super) const fn new(max_windows: usize, duration: std::time::Duration) -> Self {
        Self { windows: Vec::new(), max_windows, duration, deadline: None }
    }

    pub(super) fn trigger(&mut self, timestamp_ns: u64) -> Result<(), &'static str> {
        if self.windows.len() >= self.max_windows {
            return Ok(());
        }
        let nanos = u64::try_from(self.duration.as_nanos()).map_err(|_| "trigger window duration overflow")?;
        let position = self.windows.partition_point(|window| window.trigger_ns <= timestamp_ns);
        self.windows.insert(position, Window::new(timestamp_ns, nanos)?);
        self.deadline = Some(std::time::Instant::now() + self.duration);
        Ok(())
    }

    pub(super) fn active(&self) -> bool {
        self.deadline.is_some_and(|deadline| std::time::Instant::now() < deadline)
    }

    pub(super) fn contains(&self, timestamp_ns: u64) -> bool {
        let count = self.windows.partition_point(|window| window.trigger_ns <= timestamp_ns);
        count > 0 && self.windows[count - 1].contains(timestamp_ns)
    }
    pub(super) fn complete(&self) -> bool {
        self.windows.len() >= self.max_windows && !self.active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_individual_or_overlapping_merged_windows() -> Result<(), &'static str> {
        let windows = [Window::new(100, 20)?, Window::new(110, 20)?];
        let all = WindowIndex::new(&windows, None)?;
        assert!(!all.contains(99));
        assert!(WindowIndex::new(&windows, Some(1))?.contains(100));
        assert!(WindowIndex::new(&windows, Some(2))?.contains(110));
        assert!(!WindowIndex::new(&windows, Some(1))?.contains(120));
        assert!(all.contains(115));
        assert!(!all.contains(130));
        assert!(WindowIndex::new(&windows, Some(0)).is_err());
        assert!(WindowIndex::new(&windows, Some(3)).is_err());
        let nested = [Window::new(100, 900)?, Window::new(110, 10)?];
        assert!(WindowIndex::new(&nested, None)?.contains(130));
        assert!(Window::new(u64::MAX, 1).is_err());
        Ok(())
    }

    #[test]
    fn window_records_require_schema_three_and_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        use crate::profile::{
            codec::{ProfileReader, ProfileWriter},
            types::Record,
        };
        let mut header = super::super::tests::header();
        let window = Record::Window { trigger_ns: 100, end_ns: 120 };
        let mut old = ProfileWriter::new(Vec::new(), &header)?;
        assert!(old.write_record(&window).is_err());
        header.schema_version = 3;
        let mut writer = ProfileWriter::new(Vec::new(), &header)?;
        writer.write_record(&window)?;
        writer.write_record(&Record::PtInstruction(super::super::tests::sample()))?;
        let bytes = writer.finish(120, 0, false, "fixture", None, 0)?;
        let mut reader = ProfileReader::new(std::io::Cursor::new(bytes))?;
        assert_eq!(reader.read_record()?, Some(window));
        assert!(matches!(reader.read_record()?, Some(Record::PtInstruction(_))));
        Ok(())
    }
}
