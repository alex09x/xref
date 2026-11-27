/*
 * XRef — a time span of a recording (`profile report --from/--to`)
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
use serde::Serialize;

/// The span `profile report` keeps, in nanoseconds counted from the first sample of the recording.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeRange {
    pub from_ns: u64,
    pub to_ns: Option<u64>,
}

/// The span a report kept, in seconds from the first sample, with the samples left out on each side.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TimeWindow {
    pub from_seconds: f64,
    pub to_seconds: f64,
    pub recording_seconds: f64,
    pub samples_before: u64,
    pub samples_after: u64,
}

/// Absolute bounds `[begin, end)` of a range over a recording whose samples span `first..=last`.
pub struct Bounds {
    pub begin: u64,
    pub end: u64,
    first: u64,
    last: u64,
    pub before: u64,
    pub after: u64,
}

impl TimeRange {
    /// The range of `--from` and `--to`, when either is given.
    pub fn from_flags(from: Option<u64>, to: Option<u64>) -> Result<Option<Self>, String> {
        if from.is_none() && to.is_none() {
            return Ok(None);
        }
        Self { from_ns: from.unwrap_or(0), to_ns: to }.validate().map(Some)
    }

    pub fn validate(self) -> Result<Self, String> {
        if self.to_ns.is_some_and(|to| to <= self.from_ns) {
            return Err("--to must be later than --from".into());
        }
        Ok(self)
    }

    /// The range over a recording, refused when its samples carry no time.
    pub fn bounds(self, span: Option<(u64, u64)>) -> Result<Bounds, String> {
        let (first, last) = span.ok_or("the recording has no CPU samples to select by time")?;
        if last == 0 {
            return Err("the samples of this recording carry no timestamps; --from and --to need them".into());
        }
        let begin = first.checked_add(self.from_ns).ok_or("--from is out of range")?;
        let end = match self.to_ns {
            Some(to) => first.checked_add(to).ok_or("--to is out of range")?,
            None => last.saturating_add(1),
        };
        Ok(Bounds { begin, end, first, last, before: 0, after: 0 })
    }
}

impl Bounds {
    /// Whether a sample at `timestamp` is kept; a sample outside is counted on its side.
    pub const fn keep(&mut self, timestamp: u64) -> bool {
        if timestamp < self.begin {
            self.before += 1;
            false
        } else if timestamp >= self.end {
            self.after += 1;
            false
        } else {
            true
        }
    }

    #[allow(clippy::cast_precision_loss)] // Seconds are for display; the selection used exact nanoseconds.
    pub fn window(&self) -> TimeWindow {
        let seconds = |ns: u64| ns as f64 / 1e9;
        // Without --to the window ends at the last sample.
        let end = if self.end == self.last.saturating_add(1) { self.last } else { self.end };
        TimeWindow {
            from_seconds: seconds(self.begin - self.first),
            to_seconds: seconds(end - self.first),
            recording_seconds: seconds(self.last - self.first),
            samples_before: self.before,
            samples_after: self.after,
        }
    }
}

/// Seconds as `12`, `2.5`, `2.5s` or `500ms`, in nanoseconds.
pub fn parse_seconds(text: &str) -> Result<u64, String> {
    let (number, scale) = text
        .strip_suffix("ms")
        .map_or_else(|| (text.strip_suffix('s').unwrap_or(text), 1_000_000_000_u64), |value| (value, 1_000_000_u64));
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let digits = scale.ilog10() as usize;
    if whole.is_empty() && fraction.is_empty()
        || !whole.bytes().chain(fraction.bytes()).all(|byte| byte.is_ascii_digit())
        || fraction.len() > digits
    {
        return Err(format!("invalid time {text:?}: use seconds such as 12, 2.5 or 500ms"));
    }
    let whole = if whole.is_empty() { 0 } else { whole.parse::<u64>().map_err(|_| "time out of range")? };
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().map_err(|_| "time out of range")?
            * 10_u64.pow(u32::try_from(digits - fraction.len()).unwrap_or(0))
    };
    whole.checked_mul(scale).and_then(|value| value.checked_add(fraction)).ok_or_else(|| "time out of range".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_and_milliseconds() {
        assert_eq!(parse_seconds("12"), Ok(12_000_000_000));
        assert_eq!(parse_seconds("2.5s"), Ok(2_500_000_000));
        assert_eq!(parse_seconds(".25"), Ok(250_000_000));
        assert_eq!(parse_seconds("500ms"), Ok(500_000_000));
        assert_eq!(parse_seconds("1.5ms"), Ok(1_500_000));
        for bad in ["", "s", "-1", "1e3", "1.0000000001", "1.5.2", "1m"] {
            assert!(parse_seconds(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn keeps_the_span_from_the_first_sample_and_counts_each_side() -> Result<(), String> {
        let range = TimeRange { from_ns: 10, to_ns: Some(20) }.validate()?;
        let mut bounds = range.bounds(Some((1000, 1100)))?;
        let kept: Vec<_> = [1000, 1009, 1010, 1019, 1020, 1100].into_iter().filter(|&t| bounds.keep(t)).collect();
        assert_eq!(kept, [1010, 1019]);
        let window = bounds.window();
        assert_eq!((window.samples_before, window.samples_after), (2, 2));
        assert!((window.from_seconds - 10e-9).abs() < 1e-15 && (window.recording_seconds - 100e-9).abs() < 1e-15);
        assert!(TimeRange { from_ns: 5, to_ns: Some(5) }.validate().is_err());
        assert!(TimeRange::default().bounds(Some((0, 0))).is_err());
        assert!(TimeRange::default().bounds(None).is_err());
        // Without --to the span runs to the last sample, which is kept.
        let mut open = TimeRange { from_ns: 50, to_ns: None }.bounds(Some((1000, 1100)))?;
        assert!(open.keep(1100) && !open.keep(1049));
        assert_eq!(TimeRange::from_flags(None, None)?, None);
        assert_eq!(TimeRange::from_flags(None, Some(7))?, Some(TimeRange { from_ns: 0, to_ns: Some(7) }));
        Ok(())
    }
}
