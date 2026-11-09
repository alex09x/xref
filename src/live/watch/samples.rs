/*
 * XRef — Which accepted watch hits are kept as samples, and the written values per writer site
 * Copyright (c) 2026 Alexander Panasenko
 * Contact: alex@prod.codes
 * Author: https://prod.codes/about/
 * Project: https://github.com/alex09x/xref
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

//! Every accepted hit counts toward its writer site; a sample (the per-hit record) is kept only
//! up to `--max-samples` per watch and, with `--value-range LO HI`, only when the recovered written
//! value is in `[LO, HI)` or could not be recovered (its trap registers still tell). With
//! `--json-lines` every sample passing the range is printed as it happens, also past the cap. Each writer site also keeps the
//! least and greatest recovered value it wrote, which alone points at a rare writer.

use crate::live::types::HexAddr;
use crate::live::watch::types::{MAX_WATCH_SAMPLES_PER_TARGET, WatchHitSample, WriterSiteEntry, WrittenValueRecovery};

/// How samples are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleKeep {
    /// Samples kept per watch.
    pub max: usize,
    /// `[lo, hi)` of the written value a kept sample must have, when recovered.
    pub value_range: Option<(u64, u64)>,
    /// Print each kept sample as one JSON line when it happens.
    pub stream: bool,
}

impl Default for SampleKeep {
    fn default() -> Self {
        Self { max: MAX_WATCH_SAMPLES_PER_TARGET, value_range: None, stream: false }
    }
}

/// The recovered written value, when the store and its value were recovered.
pub const fn written(value: &WrittenValueRecovery) -> Option<u64> {
    match value {
        WrittenValueRecovery::CandidateRegisterStore { value, .. }
        | WrittenValueRecovery::CandidateImmediateStore { value, .. } => Some(value.0),
        WrittenValueRecovery::Unknown { .. } => None,
    }
}

impl SampleKeep {
    /// Whether a hit that wrote `value` passes `--value-range`: an unrecovered value passes.
    pub const fn passes(&self, value: Option<u64>) -> bool {
        match (self.value_range, value) {
            (Some((lo, hi)), Some(v)) => lo <= v && v < hi,
            _ => true,
        }
    }
}

/// Widens the site's written-value bounds by `value`.
pub fn note_site_value(site: &mut WriterSiteEntry, value: Option<u64>) {
    let Some(v) = value else { return };
    site.written_min = Some(HexAddr(site.written_min.map_or(v, |m| m.0.min(v))));
    site.written_max = Some(HexAddr(site.written_max.map_or(v, |m| m.0.max(v))));
}

/// Where a kept or dropped sample goes for one watch.
pub struct SampleSink<'a> {
    pub samples: &'a mut Vec<WatchHitSample>,
    pub truncated: &'a mut bool,
    pub value_filtered: &'a mut u64,
}

/// Keeps `sample` of the watch at `watch_va` as `keep` says: filtered out by value, streamed, then
/// stored while under the cap. Returns `false` when the `--json-lines` stdout was found closed.
pub fn keep_sample(keep: &SampleKeep, watch_va: u64, sample: WatchHitSample, sink: &mut SampleSink<'_>) -> bool {
    if !keep.passes(written(&sample.written_value)) {
        *sink.value_filtered = sink.value_filtered.saturating_add(1);
        return true;
    }
    let open = if keep.stream
        && let Ok(line) = serde_json::to_string(&serde_json::json!({ "watch": HexAddr(watch_va), "sample": &sample }))
    {
        crate::live::probe::output::emit_hit_line(&line)
    } else {
        true
    };
    if sink.samples.len() < keep.max {
        sink.samples.push(sample);
    } else {
        *sink.truncated = true;
    }
    open
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::watch::types::WriterConfidence;

    fn site() -> WriterSiteEntry {
        WriterSiteEntry {
            trap_runtime_ip: HexAddr(0x1000),
            trap_static_ip: None,
            candidate_writer_static_ip: None,
            candidate_writer_mnemonic: None,
            candidate_writer_text: None,
            writer_function: None,
            writer_function_offset: None,
            writer_symbol: None,
            confidence: WriterConfidence::OutsideKnownFunction,
            hits: 0,
            written_min: None,
            written_max: None,
            caveat: "x",
        }
    }

    #[test]
    fn value_range_passes_inside_and_unrecovered_only() {
        let keep = SampleKeep { max: 4, value_range: Some((10, 20)), stream: false };
        assert!(keep.passes(Some(10)) && keep.passes(Some(19)) && keep.passes(None));
        assert!(!keep.passes(Some(9)) && !keep.passes(Some(20)));
        assert!(SampleKeep::default().passes(Some(u64::MAX)));
    }

    #[test]
    fn site_bounds_widen_with_recovered_values_only() {
        let mut s = site();
        note_site_value(&mut s, None);
        assert_eq!((s.written_min, s.written_max), (None, None));
        for v in [7, 3, 9] {
            note_site_value(&mut s, Some(v));
        }
        assert_eq!((s.written_min, s.written_max), (Some(HexAddr(3)), Some(HexAddr(9))));
    }

    #[test]
    fn keep_sample_filters_counts_and_caps() {
        let keep = SampleKeep { max: 1, value_range: Some((0, 5)), stream: false };
        let (mut samples, mut truncated, mut filtered) = (Vec::new(), false, 0u64);
        let mk = |v: u64| -> WatchHitSample {
            WatchHitSample {
                tgid: None,
                tid: 1,
                timestamp_ns: None,
                trap_runtime_ip: HexAddr(0x1000),
                trap_static_ip: None,
                candidate_writer_static_ip: None,
                candidate_writer_text: None,
                writer_function: None,
                writer_symbol: None,
                confidence: WriterConfidence::OutsideKnownFunction,
                written_value: WrittenValueRecovery::CandidateImmediateStore {
                    width_bytes: 8,
                    value: HexAddr(v),
                    caveat: "x",
                },
                regs: None,
            }
        };
        for v in [9, 1, 2] {
            let mut sink =
                SampleSink { samples: &mut samples, truncated: &mut truncated, value_filtered: &mut filtered };
            assert!(keep_sample(&keep, 0x1000, mk(v), &mut sink));
        }
        assert_eq!((samples.len(), truncated, filtered), (1, true, 1));
        assert_eq!(written(&samples[0].written_value), Some(1));
    }
}
